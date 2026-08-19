"""Durable engagement orchestration (Temporal).

Deliberately EMPTY: importing this package must not trigger the activity
import chain. The Temporal workflow sandbox imports
`secscan.platform.workflows.engagement_workflow` directly; an eager
`__init__` would pull the activities graph (agents, application services)
into the sandbox outside the workflow module's pass-through context and
break on import-time clock reads. Consumers use
`from secscan.platform.workflows import activities, engagement_workflow`
— Python resolves submodules without an __init__ entry.
"""
