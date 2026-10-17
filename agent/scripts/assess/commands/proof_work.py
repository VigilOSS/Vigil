"""Durable proof-work operations; native launching remains the operator's job."""
from __future__ import annotations

import json
import sys
from pathlib import Path

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
            result = client.post(endpoint, payload)
    if action not in ('list', 'get'):
        if not isinstance(result, dict):
            raise AssessError('proof-work: malformed write response; inspect durable state before retrying')
        require_write_result(result, operation=f'proof-work {action}', positive_ids=('id',))
    print(json.dumps(result, indent=2))
