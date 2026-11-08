"""Shared dispatch context is captured once and loaded by immutable reference."""
import argparse
import hashlib

import pytest

from assess.commands import agent
from assess.lib.client import AssessError
from test_dispatch_launch_packets import setup_start


def _brief_args(monkeypatch, tmp_path):
    args, client = setup_start(monkeypatch, tmp_path)
    source = tmp_path / 'standing.md'
    source.write_text('Acme engagement facts and standing instructions.\n' * 200)
    args.standing_brief_file = str(source)
    return args, client, source


def test_shared_brief_is_captured_once_and_packet_carries_reference(monkeypatch, tmp_path, capsys):
    args, client, source = _brief_args(monkeypatch, tmp_path)
    agent._start(args)
    first = client.writes[0]['prompt_packet']
    reference = first['context']['standing_brief']
    captured = tmp_path / reference['path']
    assert captured.read_bytes() == source.read_bytes()
    assert reference['sha256'] == hashlib.sha256(captured.read_bytes()).hexdigest()
    assert 'text' not in reference
    assert source.read_text() not in first['rendered_prompt']
    assert reference['path'] in first['rendered_prompt']
    assert reference['sha256'] in first['rendered_prompt']
    assert reference['path'] in capsys.readouterr().out
    agent._start(args)
    assert client.writes[1]['prompt_packet']['context']['standing_brief'] == reference
    assert list((tmp_path / 'tools/dispatch-briefs').glob('*.md')) == [captured]


def test_brief_edit_creates_new_capture_without_changing_prior_dispatch(monkeypatch, tmp_path):
    args, client, source = _brief_args(monkeypatch, tmp_path)
    agent._start(args)
    old = client.writes[0]['prompt_packet']['context']['standing_brief']
    old_bytes = (tmp_path / old['path']).read_bytes()
    source.write_text('Acme updated standing instructions.\n')
    agent._start(args)
    new = client.writes[1]['prompt_packet']['context']['standing_brief']
    assert new['sha256'] != old['sha256']
    assert (tmp_path / old['path']).read_bytes() == old_bytes
    assert (tmp_path / new['path']).read_bytes() == source.read_bytes()


def test_tampered_brief_refuses_launch_and_continuation(monkeypatch, tmp_path):
    args, client, _source = _brief_args(monkeypatch, tmp_path)
    agent._start(args)
    payload = client.writes[0]
    reference = payload['prompt_packet']['context']['standing_brief']
    (tmp_path / reference['path']).write_text('Different context')
    packet = dict(payload['prompt_packet'])
    packet['sha256'] = hashlib.sha256(packet['rendered_prompt'].encode()).hexdigest()
    row = {'id': 7, **payload, 'prompt_packet': packet, 'status': 'in-progress', 'launch_required': True}
    with pytest.raises(AssessError, match='standing brief'):
        agent._build_launch_receipt(row, type('Config', (), {'engagement_dir': str(tmp_path)})(), expected_identity=payload)
    client.get_dispatch = lambda _: {'id': 7, 'agent_id': 'acme-lane', 'agent_role': 'vulnerability-analyst', 'status': 'failed', 'assessment_mode': 'web'}
    client.get = lambda _: packet
    args.extra, args.agent_id, args.task, args.assessment_mode = ['acme-lane'], 'acme-next', 'Finish Acme review', None
    with pytest.raises(AssessError, match='standing brief'):
        agent._continue(args)
    assert len(client.writes) == 1


def test_continuation_retains_captured_brief_after_original_changes(monkeypatch, tmp_path):
    args, client, source = _brief_args(monkeypatch, tmp_path)
    agent._start(args)
    packet = client.writes[0]['prompt_packet']
    packet['sha256'] = hashlib.sha256(packet['rendered_prompt'].encode()).hexdigest()
    original = packet['context']['standing_brief']
    source.write_text('A later wave has different context.')
    client.get_dispatch = lambda _: {'id': 7, 'agent_id': 'acme-lane', 'agent_role': 'vulnerability-analyst', 'status': 'failed', 'assessment_mode': 'web'}
    client.get = lambda _: packet
    args.extra, args.agent_id, args.task, args.assessment_mode = ['acme-lane'], 'acme-next', 'Finish Acme review', None
    agent._continue(args)
    continued = client.writes[1]['prompt_packet']
    assert continued['context']['standing_brief'] == original
    assert source.read_text() not in continued['rendered_prompt']


def test_brief_flag_and_shared_json_context_are_supported(monkeypatch, tmp_path):
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    args = parser.parse_args(['agent', 'start', '--standing-brief-file', 'brief.md'])
    assert args.standing_brief_file == 'brief.md'
    args, client, source = _brief_args(monkeypatch, tmp_path)
    args.standing_brief_file = None
    args.prompt_context = {'standing_brief_file': str(source)}
    agent._start(args)
    assert client.writes[0]['prompt_packet']['context']['standing_brief']['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_dry_run_validates_brief_without_publishing_capture(monkeypatch, tmp_path):
    args, client, _source = _brief_args(monkeypatch, tmp_path)
    args.dry_run = True
    agent._start(args)
    assert client.writes == []
    assert not (tmp_path / 'tools/dispatch-briefs').exists()


def test_brief_flag_overrides_shared_json_without_retaining_authoring_path(monkeypatch, tmp_path):
    args, client, source = _brief_args(monkeypatch, tmp_path)
    args.prompt_context = {'standing_brief_file': 'other-brief.md'}
    agent._start(args)
    context = client.writes[0]['prompt_packet']['context']
    assert context['standing_brief']['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert context.get('standing_brief_file') is None


def test_public_context_cannot_forge_captured_brief(monkeypatch, tmp_path):
    args, client = setup_start(monkeypatch, tmp_path)
    args.prompt_context = {'standing_brief': {'path': 'pretend.md', 'sha256': 'a' * 64}}
    with pytest.raises(SystemExit):
        agent._start(args)
    assert client.writes == []


@pytest.mark.parametrize('present', [False, True])
def test_handoff_carries_the_same_brief_reference_and_artifact_state(monkeypatch, tmp_path, capsys, present):
    from test_handoff_renderer_provenance import _run_renderer
    reference = {'path': 'tools/dispatch-briefs/' + 'a' * 64 + '.md', 'sha256': 'a' * 64}
    _run_renderer(monkeypatch, tmp_path, dispatch_slugs=[], handoff_slugs=[],
                  packet_context={'standing_brief': reference}, max_lines=0,
                  present_paths=(reference['path'],) if present else ())
    text = capsys.readouterr().out
    assert reference['path'] in text
    assert reference['sha256'] in text
    assert f"`{reference['path']}` (state: {'present' if present else 'missing'})" in text


def test_referencing_shared_context_reduces_packet_bytes(monkeypatch, tmp_path):
    args, client, source = _brief_args(monkeypatch, tmp_path)
    args.standing_brief_file, args.packet_file = None, str(source)
    agent._start(args)
    inline = client.writes[0]['prompt_packet']['rendered_prompt'].encode()
    args.standing_brief_file, args.packet_file = str(source), None
    agent._start(args)
    referenced = client.writes[1]['prompt_packet']['rendered_prompt'].encode()
    assert len(referenced) < len(inline)
    print(f'Packet bytes: inline={len(inline)}, referenced={len(referenced)}')
