# tools.py
# Tool definitions for integrating IronClaw-Security as LLM tools / skills.

ironclaw_scan_tool = {
    "name": "ironclaw_scan",
    "description": (
        "Evaluate a single target (text, URL, GitHub repo, or archive) for security "
        "risks such as prompt injection, code execution, exfiltration, or other "
        "malicious patterns. Returns a normalized action ('allow', 'warn', 'block', "
        "or 'quarantine') plus detailed findings. Use this BEFORE executing or "
        "following untrusted content."
    ),
    "parameters": {
        "type": "object",
        "required": ["target_type", "target_value"],
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["text", "url", "githubrepo", "archive"],
                "description": "Type of target to scan."
            },
            "target_value": {
                "type": "string",
                "description": (
                    "Content to scan: raw text, URL string, GitHub repo identifier, "
                    "or archive name/path."
                )
            },
            "mode": {
                "type": "string",
                "enum": ["enforce", "monitor", "strict"],
                "default": "enforce",
                "description": (
                    "Policy mode. 'enforce' uses the engine decision as-is. "
                    "'monitor' only warns on risky items (no hard block). "
                    "'strict' escalates warnings to quarantine."
                )
            },
            "source": {
                "type": "string",
                "nullable": True,
                "description": (
                    "Where this input came from, e.g. 'chat', 'file', 'github', "
                    "'url', 'system_prompt'."
                )
            },
            "session_id": {
                "type": "string",
                "nullable": True,
                "description": "Caller-defined session or conversation identifier."
            },
            "user_id": {
                "type": "string",
                "nullable": True,
                "description": "Caller-defined user identifier (opaque)."
            },
            "context": {
                "type": "string",
                "nullable": True,
                "description": (
                    "Short context description, e.g. 'incoming user message', "
                    "'tool output', 'system prompt'."
                )
            }
        }
    }
}


ironclaw_scan_batch_tool = {
    "name": "ironclaw_scan_batch",
    "description": (
        "Batch-evaluate multiple targets for security risks in a single call. "
        "Each item has its own client_id so you can correlate results back to "
        "your messages or files."
    ),
    "parameters": {
        "type": "object",
        "required": ["items"],
        "properties": {
            "items": {
                "type": "array",
                "description": "List of targets to scan.",
                "items": {
                    "type": "object",
                    "required": ["client_id", "target_type", "target_value"],
                    "properties": {
                        "client_id": {
                            "type": "string",
                            "description": (
                                "Your identifier for this item (e.g. message ID). "
                                "Echoed back in the response."
                            )
                        },
                        "target_type": {
                            "type": "string",
                            "enum": ["text", "url", "githubrepo", "archive"]
                        },
                        "target_value": {
                            "type": "string"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["enforce", "monitor", "strict"],
                            "default": "enforce"
                        },
                        "source": {
                            "type": "string",
                            "nullable": True
                        },
                        "session_id": {
                            "type": "string",
                            "nullable": True
                        },
                        "user_id": {
                            "type": "string",
                            "nullable": True
                        },
                        "context": {
                            "type": "string",
                            "nullable": True
                        }
                    }
                }
            }
        }
    }
}