"""vigil assess emit-event — fire-and-forget POST to /events."""
from __future__ import annotations


from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("emit-event", help="POST a runtime event (fire-and-forget)")
    p.add_argument("event_type")
    p.add_argument("phase")
    p.add_argument("task")
    p.add_argument("agent")
    p.add_argument("summary")
    p.set_defaults(func=run)


def run(args) -> None:
    try:
        cfg = load_config(args.engagement_dir)
    except SystemExit:
        # If we can't resolve config, silently exit (fire-and-forget)
        return

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": args.event_type,
            "phase": args.phase,
            "task_name": args.task,
            "agent_name": args.agent,
            "summary": args.summary,
        })
