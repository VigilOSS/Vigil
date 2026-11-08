from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from assess.commands import agent


def _row():
    return {'id': 44, 'file_path': 'src/acme.php', 'loc': 21, 'repo_id': 7,
            'repo_generation': 3, 'status': 'processing', 'classification': 'core',
            'lease_token': 'acme-lease', 'applicable_vuln_classes': ['injection'],
            'path_suggested_vuln_classes': []}


class SelectedFacts:
    def __init__(self):
        self.calls = []

    def get(self, endpoint):
        self.calls.append(endpoint)
        path = urlsplit(endpoint).path
        params = parse_qs(urlsplit(endpoint).query)
        if path == 'findings/count':
            return {'total': 123456}
        if path == 'code/analysis-queue':
            assert params['item_id'] == ['44']
            return {'items': [_row()], 'total': 1, 'count': 1, 'offset': 0, 'has_more': False}
        if path == 'code/files':
            assert params['file_path'] == ['src/acme.php']
            return {'items': [_row()], 'total': 1, 'count': 1, 'offset': 0, 'has_more': False}
        raise AssertionError(endpoint)


def test_finding_total_uses_count_without_serializing_findings():
    client = SelectedFacts()
    assert agent._backend_finding_total(client) == 123456
    assert client.calls == ['findings/count']


def test_queue_selection_renders_current_backend_floor_with_one_read():
    client = SelectedFacts()
    rendered = '\n'.join(agent._backend_queue_manifest(client, [44], repo_id=7, repo_generation=3))
    assert 'src/acme.php' in rendered
    assert 'common_applicable_vuln_classes=injection' in rendered
    assert len(client.calls) == 1


def test_json_lane_selection_reads_only_selected_queue_facts(tmp_path):
    client = SelectedFacts()
    lane = tmp_path / 'lane.json'
    lane.write_text(json.dumps([{'id': 44, 'repo_generation': 3, 'repo': {'id': 7},
        'file': {'file_path': 'forged.php', 'loc': 999}, 'applicable_vuln_classes': ['ssrf']}]))
    rendered = '\n'.join(agent._lane_file_manifest(lane, client=client,
                        source_identity=['repo_id: 7', 'repo_generation: 3']))
    assert '"src/acme.php" (21 LOC' in rendered
    assert '- common_applicable_vuln_classes: injection' in rendered
    assert len(client.calls) == 1


def test_path_lane_selection_reads_only_exact_paths(tmp_path):
    client = SelectedFacts()
    lane = tmp_path / 'lane.txt'
    lane.write_text('src/acme.php\n')
    rendered = '\n'.join(agent._lane_file_manifest(lane, client=client,
                        source_identity=['repo_id: 7', 'repo_generation: 3']))
    assert '"src/acme.php" (21 LOC' in rendered
    assert len(client.calls) == 1


@pytest.mark.parametrize('total', [True, -1, '12', None])
def test_invalid_count_is_advisory_not_a_fabricated_total(total):
    class Client:
        def get(self, endpoint):
            return {'total': total}
    assert agent._backend_finding_total(Client()) is None


def test_required_family_names_preserve_the_complete_backend_floor():
    names = [f'family-{index}' for index in range(40)]
    assert agent._vuln_class_names(names) == tuple(names)


def test_path_lane_facts_must_match_the_packet_generation(tmp_path):
    class Client(SelectedFacts):
        def get(self, endpoint):
            page = super().get(endpoint)
            page['items'][0]['repo_generation'] = 2
            return page
    lane = tmp_path / 'lane.txt'
    lane.write_text('src/acme.php\n')
    with pytest.raises(SystemExit):
        agent._lane_file_manifest(lane, client=Client(),
                                 source_identity=['repo_id: 7', 'repo_generation: 3'])


def test_lane_facts_require_an_explicit_backend_family_floor(tmp_path):
    class Client(SelectedFacts):
        def get(self, endpoint):
            page = super().get(endpoint)
            page['items'][0]['applicable_vuln_classes'] = None
            return page
    lane = tmp_path / 'lane.json'
    lane.write_text(json.dumps([{'id': 44, 'repo_generation': 3, 'repo': {'id': 7},
                                'file': {'file_path': 'src/acme.php', 'loc': 21}}]))
    with pytest.raises(SystemExit):
        agent._lane_file_manifest(lane, client=Client(),
                                 source_identity=['repo_id: 7', 'repo_generation: 3'])


def test_exact_selection_queries_preserve_all_literal_paths_in_bounded_batches():
    paths = [f'src/Acme {index}/a[1]+界.php' for index in range(1800)]
    queries = agent._selected_fact_queries('code/files', 7, 'file_path', paths)
    selected = []
    for query in queries:
        params = parse_qs(urlsplit(query).query)
        selected.extend(params['file_path'])
        assert len(params['file_path']) <= 1000
        assert len(query.encode('utf-8')) <= 8000
    assert selected == paths


def test_oversized_lane_selection_fails_before_backend_work(tmp_path):
    lane = tmp_path / 'lane.json'
    lane.write_text(json.dumps([{'id': index + 1, 'repo_generation': 3, 'repo': {'id': 7},
                                 'file': {}} for index in range(5001)]))
    class Client:
        def get(self, endpoint):
            raise AssertionError('oversized selection reached backend')
    with pytest.raises(SystemExit):
        agent._lane_file_manifest(lane, client=Client(),
                                 source_identity=['repo_id: 7', 'repo_generation: 3'])


def test_long_unicode_paths_use_body_lookup_without_losing_literal_facts(tmp_path):
    long_paths = ['src/' + '界' * 3000 + f'/Acme{index}.php' for index in range(2)]
    paths = ['src/acme.php', *long_paths, 'src/other.php']
    calls = []

    def page(selected):
        return {'items': [dict(_row(), file_path=path, loc=index + 10)
                          for index, path in enumerate(selected)],
                'total': len(selected), 'count': len(selected), 'offset': 0, 'has_more': False}

    class Client:
        def get(self, endpoint):
            calls.append(('GET', endpoint))
            assert len(endpoint.encode('utf-8')) <= 8000
            selected = parse_qs(urlsplit(endpoint).query)['file_path']
            return page(selected)

        def post(self, endpoint, payload):
            calls.append(('POST', endpoint, payload))
            assert endpoint == 'code/files/lookup'
            assert payload == {'repo_id': 7, 'file_paths': long_paths}
            return page(payload['file_paths'])

    lane = tmp_path / 'lane.txt'
    lane.write_text('\n'.join(paths))
    rendered = '\n'.join(agent._lane_file_manifest(lane, client=Client(),
                              source_identity=['repo_id: 7', 'repo_generation: 3']))
    for path in paths:
        assert json.dumps(path, ensure_ascii=False) in rendered
    assert [call for call in calls if call[0] == 'POST'] == [
        ('POST', 'code/files/lookup', {'repo_id': 7, 'file_paths': long_paths})]
    assert all(len(call[1].encode('utf-8')) <= 8000 for call in calls if call[0] == 'GET')
