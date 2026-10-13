"""Durable proof-work operations; native launching remains the operator's job."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config


def register(subparsers) -> None:
    parser = subparsers.add_parser('proof-work', help='Prepare, claim, inspect, and recover durable proof work.')
    actions = parser.add_subparsers(dest='proof_work_action', required=True)
    for name in ('list', 'get', 'prepare', 'claim', 'approve', 'revoke', 'update', 'reconcile', 'release'):
        action = actions.add_parser(name)
        if name not in ('list', 'prepare'):
            action.add_argument('work_id', type=int)
        if name == 'prepare':
            action.add_argument('finding_slug')
            action.add_argument('--route', required=True, choices=('code', 'web'))
            action.add_argument('--objective', required=True)
            action.add_argument('--host', action='append', default=[])
        if name == 'claim':
            action.add_argument('--agent-id', required=True)
            action.add_argument('--agent-role', required=True)
            action.add_argument('--task')
            action.add_argument('--prompt-context-json', required=True,
                                help='Canonical dispatch context JSON or @file, as for agent start --emit-prompt.')
            traffic = action.add_mutually_exclusive_group(required=True)
            traffic.add_argument('--rate-budget', help='Per-specialist target-traffic budget, as for agent start.')
            traffic.add_argument('--no-target-traffic', action='store_true')
            action.add_argument('--dispatch-file', help='Additional canonical DispatchCreate JSON, including instruction identity.')
        if name == 'update':
            action.add_argument('--agent-id', required=True)
            action.add_argument('--status', required=True, choices=('claimed', 'blocked', 'finished'))
            action.add_argument('--blocker', default='')
            action.add_argument('--run-id', type=int)
        if name == 'release':
            action.add_argument('--reason', required=True)
        action.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    action = args.proof_work_action
    endpoint = 'proof-work'
    payload = {}
    if action == 'prepare':
        payload = {'finding_slug': args.finding_slug, 'route': args.route,
                   'objective': args.objective, 'target_hosts': args.host}
    elif action != 'list':
        endpoint += f'/{args.work_id}'
    if action == 'claim':
        if args.dispatch_file:
            try:
                payload = json.loads(Path(args.dispatch_file).read_text(encoding='utf-8'))
            except (OSError, ValueError) as exc:
                raise AssessError(f'proof-work claim: invalid dispatch file: {exc}') from exc
            if not isinstance(payload, dict):
                raise AssessError('proof-work claim: dispatch file must be an object')
        payload.update(agent_id=args.agent_id, agent_role=args.agent_role)
        if args.task:
            payload['task'] = args.task
        from assess.commands.agent import _attach_dispatch_provenance
        for warning in _attach_dispatch_provenance(payload, cfg):
            print(f'WARN proof-work claim: {warning}', file=sys.stderr)
        endpoint += '/claim'
    elif action in ('approve', 'revoke'):
        endpoint += '/approval'
        payload = {'approved': action == 'approve'}
    elif action in ('reconcile', 'release'):
        endpoint += f'/{action}'
        if action == 'release':
            payload = {'reason': args.reason}
    elif action == 'update':
        payload = {'agent_id': args.agent_id, 'status': args.status, 'blocker': args.blocker}
        if args.run_id is not None:
            payload['run_id'] = args.run_id
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if action in ('list', 'get'):
            result = client.get(endpoint)
        elif action == 'update':
            result = client.patch(endpoint, payload)
        else:
            if action == 'claim':
                work = client.get(f'proof-work/{args.work_id}')
                _attach_claim_prompt(payload, work, args, cfg, client)
            result = client.post(endpoint, payload)
    if action not in ('list', 'get'):
        if not isinstance(result, dict):
            raise AssessError('proof-work: malformed write response; inspect durable state before retrying')
        require_write_result(result, operation=f'proof-work {action}', positive_ids=('id',))
    print(json.dumps(result, indent=2))


def _attach_claim_prompt(payload, work, args, cfg, client) -> None:
    """Use the normal dispatch renderer before acquiring atomic ownership."""
    from assess.commands.agent import _code_source_identity_lines, _dispatch_prompt, _load_prompt_context

    context = _load_prompt_context(args)
    phase = work['authorized_phase']
    if context['authorized_phase'] != phase:
        raise AssessError(f'proof-work claim: authorized_phase must be {phase}')
    source = (work.get('binding') or {}).get('source_binding')
    source_identity = []
    if source:
        source_identity = _code_source_identity_lines(
            client, agent_role=payload['agent_role'], requested_repo_id=source['repo_id'],
        )
        observed = dict(line.split(': ', 1) for line in source_identity if ': ' in line)
        if any(str(observed.get(key)) != str(source[key])
               for key in ('repo_id', 'repo_generation', 'source_manifest_digest')):
            raise AssessError('proof-work claim: source identity changed; reconcile and prepare current work')
    payload['task'] = payload.get('task') or work['objective']
    payload['dispatch_mode'] = 'deep-manual'
    payload['finding_slugs'] = [work['finding_slug']]
    render_args = SimpleNamespace(prompt_context=context, rate_budget=args.rate_budget,
                                  no_target_traffic=args.no_target_traffic)
    assignment = (f"## Proof assignment\nproof_route: {work['route']}\n"
                  f"proof_work_id: {work['id']}\nfinding_slug: {work['finding_slug']}\n"
                  f"target_hosts: {', '.join(work['target_hosts']) or 'none — local execution only'}\n"
                  f"proof command attribution: pass `--agent-name {payload['agent_id']}` on every audited run used by a proof receipt; use this dispatch agent_id, not the role name.\n"
                  'Read `vigil assess proof-work get ' + str(work['id']) +
                  '` before execution; use only its current authorized route and targets.')
    rendered = assignment + '\n\n' + _dispatch_prompt(
        payload, engagement_dir=Path(cfg.engagement_dir), agent_root=Path(cfg.agent_root),
        source_identity=source_identity, args=render_args, client=client,
    )
    payload['prompt_packet'] = {'schema': 'dispatch-prompt/v1', 'context': context,
                                'rendered_prompt': rendered}
