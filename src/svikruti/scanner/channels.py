"""Queues, task runners and event buses between a caller and a vendor.

`signup()` publishes the new user to a queue; a worker in another file reads
the queue and sends the user to Mailchimp. Nothing in `signup()` names
Mailchimp, so following calls alone never connects the two. This module finds
both ends of the hop and joins them on the channel name:

* producers: `send_welcome.delay(user.email)`, `producer.send("user-signup", payload)`,
  `emitter.emit("user.created", user)`, `kafkaTemplate.send(TOPIC, user)`,
  `publisher.publishEvent(new UserRegistered(user))`, `WelcomeJob.perform_later(user)`,
  `SendWelcome::dispatch($user)`, `queue.add("welcome", { email })`;
* consumers: `@shared_task def send_welcome(...)`, `@KafkaListener(topics = TOPIC)`,
  `@RabbitListener(queues = "x")`, `@EventListener void on(UserRegistered e)`,
  `@OnEvent("user.created")`, `@EventPattern(...)`, `emitter.on("user.created", fn)`,
  `new Worker("welcome", async job => ...)`, `channel.consume("x", cb)`,
  `class WelcomeJob ... def perform`, Laravel jobs and listeners.

A channel is a topic, queue or event name (string constants are resolved), a
task's function or class name, or an event class. The data is what the
producer passes; the vendor is whatever the consumer's code reaches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Tuple

if TYPE_CHECKING:  # pragma: no cover
    from svikruti.scanner.flows import _SourceFile

_NAME = r"[A-Za-z_$][\w$]*"
_CHANNEL_ARG = rf"""(?:["'`]([^"'`\n]{{1,120}})["'`]|({_NAME}(?:\.{_NAME})?))"""

# ---------------------------------------------------------------- producers
_TASK_CALL_RE = re.compile(
    rf"(?<![\w$.])({_NAME})\s*(?:\.|::)\s*(?:delay|apply_async|s|si|send|send_with_options|perform_async|perform_in|perform_at|perform_later|perform_now|dispatch|dispatch_sync|dispatchSync|dispatch_now|enqueue)\s*\("
)
_ENQUEUE_FUNC_RE = re.compile(rf"\b(?:enqueue|enqueue_call|enqueue_in|enqueue_at|add_job|schedule)\s*\(\s*(?:func\s*=\s*)?({_NAME}(?:\.{_NAME})*)\s*[,)]")
_SEND_TASK_RE = re.compile(r"""\bsend_task\s*\(\s*["']([\w.]+)["']""")
_NEW_EVENT_RE = re.compile(rf"\b(?:publishEvent|publish_event|event|dispatch|Event::dispatch|broadcast|raise_event|emit_event)\s*\(\s*new\s+({_NAME})\s*\(")
_TOPIC_CALL_RE = re.compile(
    rf"(?:\.|->)\s*(?:emit|emitAsync|publish|send|produce|add|sendToQueue|convertAndSend|sendMessage|send_message|Publish|PublishMessage|lpush|rpush|xadd|basic_publish)\s*\(\s*(?:topic\s*=\s*|queue\s*=\s*|QueueUrl\s*:\s*)?{_CHANNEL_ARG}\s*[,)]"
)
_TOPIC_KEY_RE = re.compile(rf"""\b(?:topic|queue|routing_key|routingKey|subject|channel|QueueUrl|TopicArn|queueName)\s*[:=]\s*{_CHANNEL_ARG}""")
_TOPIC_KEY_CALLS_RE = re.compile(r"(?:\.|->)\s*(?:send|publish|produce|sendMessage|send_message|basic_publish|sendBatch|publishBatch)\s*\(")
_QUEUE_VAR_RE = re.compile(rf"""(?:const|let|var|self\.|this\.)?\s*({_NAME})\s*=\s*new\s+(?:Queue|Bull|BeeQueue|Bee)\s*\(\s*["'`]([^"'`]+)["'`]""")
_QUEUE_ADD_RE = re.compile(rf"(?<![\w$])(?:this\.|self\.)?({_NAME})\s*\.\s*(?:add|addBulk|createJob)\s*\(")
_DJANGO_SIGNAL_SEND_RE = re.compile(rf"(?<![\w$.])({_NAME})\s*\.\s*send(?:_robust)?\s*\(\s*sender\s*=")

# ---------------------------------------------------------------- consumers
_PY_TASK_DECORATOR_RE = re.compile(r"^\s*@(?:[\w.]+\.)?(?:task|shared_task|actor|job|periodic_task|db_task)\b")
_TOPIC_DECORATOR_RE = re.compile(
    rf"^\s*@(?:[\w.]+\.)?(?:KafkaListener|RabbitListener|JmsListener|SqsListener|StreamListener|KafkaHandler|OnEvent|EventPattern|MessagePattern|Process|Processor|subscriber|subscribe|consumer|on_message|agent|receiver|listener|Subscribe|OnQueueActive|SubscribeMessage)\s*\((.*)"
)
_EVENT_LISTENER_RE = re.compile(r"^\s*@(?:EventListener|TransactionalEventListener|Subscribe|Listen)\b")
_ON_CALL_RE = re.compile(
    rf"(?:\.|->)\s*(?:on|once|addListener|subscribe|Subscribe|QueueSubscribe|process|consume|listen|basic_consume|handle|register)\s*\(\s*(?:queue\s*=\s*)?{_CHANNEL_ARG}\s*,\s*(.*)$"
)
_WORKER_RE = re.compile(rf"\bnew\s+Worker\s*\(\s*{_CHANNEL_ARG}\s*,\s*(.*)$")
_CALLBACK_KW_RE = re.compile(rf"\bon_message_callback\s*=\s*({_NAME}(?:\.{_NAME})*)")
_KAFKAJS_SUBSCRIBE_RE = re.compile(rf"""\.subscribe\s*\(\s*\{{[^}}]*\btopics?\s*:\s*\[?\s*{_CHANNEL_ARG}""")
_KAFKAJS_RUN_RE = re.compile(r"\.run\s*\(\s*\{")
_RB_JOB_CLASS_RE = re.compile(r"^\s*class\s+(\w+)\s*(?:<\s*(?:ApplicationJob|ActiveJob::Base|\w*Job))?")
_RB_JOB_MARKER_RE = re.compile(r"(?:\binclude\s+Sidekiq::(?:Job|Worker)|<\s*(?:ApplicationJob|ActiveJob::Base))")
_PHP_QUEUED_CLASS_RE = re.compile(r"^\s*(?:final\s+)?class\s+(\w+)\b[^{]*\bimplements\b[^{]*\bShouldQueue\b")
_PHP_HANDLE_RE = re.compile(rf"\bfunction\s+handle\s*\(\s*({_NAME})\s+\$")
_CLASS_RE = re.compile(rf"^\s*(?:export\s+)?(?:default\s+)?(?:public\s+|private\s+|final\s+|abstract\s+)*class\s+({_NAME})")
_CONSTANT_RE = re.compile(
    rf"""^\s*(?:export\s+)?(?:(?:public|private|protected|internal|static|final|const|readonly|val|var|let)\s+)*(?:String\s+|string\s+|str\s*)?([A-Z][A-Z0-9_]{{2,}})\s*(?::\s*\w+\s*)?[:=]\s*["']([^"'\n]{{1,120}})["']"""
)


@dataclass
class Consumer:
    channel: str
    rel: str
    name: str
    start: int
    end: int


@dataclass
class Producer:
    channel: str
    rel: str
    index: int


def _key(kind: str, value: str, constants: Dict[str, str], literal: bool = False) -> str:
    value = value.strip()
    if kind == "topic":
        if not literal:
            tail = value.split(".")[-1]
            if tail in constants:
                value = constants[tail]
            elif value in constants:
                value = constants[value]
            else:
                return f"topic-id:{tail.lower()}"
        # An SQS URL or SNS ARN names the queue in its last path segment.
        value = re.split(r"[/:]", value.rstrip("/"))[-1] if re.match(r"^(?:https?://|arn:)", value) else value
    if kind in {"task", "event"}:
        value = value.split(".")[-1]
    return f"{kind}:{value.lower()}"


def _arg_key(kind: str, match: "re.Match[str]", constants: Dict[str, str], group: int = 1) -> str:
    literal = match.group(group)
    return _key(kind, literal if literal is not None else match.group(group + 1), constants, literal=literal is not None)


def constants_of(sources: List["_SourceFile"]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for source in sources:
        if not any(hint in source.lowered for hint in ("topic", "queue", "event", "channel", "subject", "stream")):
            continue
        for line in source.lines:
            match = _CONSTANT_RE.match(line)
            if match:
                found.setdefault(match.group(1), match.group(2))
    return found


def _block_end(lines: List[str], index: int, limit: int = 300) -> int:
    """Last line of the brace block that opens on or after ``index``."""
    depth, opened = 0, False
    for offset in range(index, min(index + limit, len(lines))):
        text = re.sub(r"""(["'`])(?:\\.|(?!\1).)*\1""", "", lines[offset])
        for char in text:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth <= 0:
                    return offset
    return index


def _python_block_end(lines: List[str], index: int) -> int:
    indent = len(lines[index]) - len(lines[index].lstrip())
    end = index
    for offset in range(index + 1, len(lines)):
        text = lines[offset]
        if text.strip() and len(text) - len(text.lstrip()) <= indent:
            break
        end = offset
    return end


def _next_function(source: "_SourceFile", index: int, within: int = 6):
    return next((function for function in sorted(source.functions, key=lambda f: f.start) if index < function.start <= index + within), None)


def _handler_range(source: "_SourceFile", index: int, rest: str, by_name: Dict[str, List[Tuple["_SourceFile", object]]]) -> List[Tuple[str, str, int, int]]:
    """(rel, name, start, end) for a callback given inline or by name."""
    callback = rest.strip()
    named = re.match(rf"(?:this\.|self\.)?({_NAME})\s*(?:\.bind\([^)]*\))?\s*[,)]", callback)
    if named and named.group(1) not in {"async", "function", "lambda", "func"}:
        hits = [(src.rel, fn.name, fn.start, fn.end) for src, fn in by_name.get(named.group(1), [])]
        own = [hit for hit in hits if hit[0] == source.rel]
        return (own or hits)[:3]
    if source.path.suffix.lower() == ".py":
        return []
    end = _block_end(source.lines, index)
    return [(source.rel, "<callback>", index, end)] if end > index else []


def find_consumers(sources: List["_SourceFile"], constants: Dict[str, str]) -> List[Consumer]:
    by_name: Dict[str, List[Tuple["_SourceFile", object]]] = {}
    for source in sources:
        for function in source.functions:
            by_name.setdefault(function.name, []).append((source, function))
    out: List[Consumer] = []
    for source in sources:
        lines, suffix = source.lines, source.path.suffix.lower()
        kafkajs_topics: List[str] = []
        for index, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith(("//", "#", "*", "/*")) and not stripped.startswith("#["):
                continue
            if _PY_TASK_DECORATOR_RE.match(line):
                function = _next_function(source, index)
                if function is not None:
                    out.append(Consumer(_key("task", function.name, constants), source.rel, function.name, function.start, function.end))
                continue
            decorator = _TOPIC_DECORATOR_RE.match(line)
            if decorator:
                args = decorator.group(1)
                channels = [
                    m for m in re.finditer(_CHANNEL_ARG, args)
                    if not re.fullmatch(r"(?:topics?|queues?|destination|value|id|groupId|group_id|containerFactory|sender|true|false|True|False|None|null)", m.group(1) or m.group(2) or "")
                ]
                if "@Processor" in line or re.match(r"^\s*@(?:[\w.]+\.)?Processor\b", line):
                    following = next((offset for offset in range(index + 1, min(index + 4, len(lines))) if _CLASS_RE.match(lines[offset])), None)
                    if following is not None and channels:
                        out.append(Consumer(_arg_key("topic", channels[0], constants), source.rel, _CLASS_RE.match(lines[following]).group(1), following, _block_end(lines, following)))
                    continue
                function = _next_function(source, index)
                if function is not None and channels:
                    kind = "signal" if re.match(r"^\s*@(?:[\w.]+\.)?receiver\b", line) else "topic"
                    for channel in channels[:3]:
                        key = _arg_key("topic", channel, constants) if kind == "topic" else f"signal:{(channel.group(1) or channel.group(2)).split('.')[-1].lower()}"
                        out.append(Consumer(key, source.rel, function.name, function.start, function.end))
                continue
            if _EVENT_LISTENER_RE.match(line):
                function = _next_function(source, index)
                if function is not None:
                    signature = "\n".join(lines[function.start : function.start + 3])
                    typed = re.search(rf"\(\s*(?:final\s+)?({_NAME})(?:<[^>]*>)?\s+\w+\s*[,)]", signature) or re.search(rf"\(\s*\w+\s*:\s*({_NAME})", signature)
                    if typed:
                        out.append(Consumer(_key("event", typed.group(1), constants), source.rel, function.name, function.start, function.end))
                continue
            for pattern in (_ON_CALL_RE, _WORKER_RE):
                match = pattern.search(line)
                if match:
                    for rel, name, start, end in _handler_range(source, index, match.group(3), by_name):
                        out.append(Consumer(_arg_key("topic", match, constants), rel, name, start, end))
                    break
            callback = _CALLBACK_KW_RE.search(line)
            if callback:
                statement = "\n".join(lines[index : index + 4])
                queue = re.search(rf"\bqueue\s*=\s*{_CHANNEL_ARG}", statement)
                if queue:
                    for src, function in by_name.get(callback.group(1).split(".")[-1], [])[:3]:
                        out.append(Consumer(_arg_key("topic", queue, constants), src.rel, function.name, function.start, function.end))
            subscribed = _KAFKAJS_SUBSCRIBE_RE.search(line)
            if subscribed:
                kafkajs_topics.append(_arg_key("topic", subscribed, constants))
            if kafkajs_topics and _KAFKAJS_RUN_RE.search(line):
                for key in kafkajs_topics:
                    out.append(Consumer(key, source.rel, "<consumer.run>", index, _block_end(lines, index)))
        # Class-based jobs: Sidekiq / ActiveJob (Ruby), ShouldQueue jobs and event listeners (Laravel).
        if suffix == ".rb" and _RB_JOB_MARKER_RE.search("\n".join(lines)):
            for index, line in enumerate(lines):
                match = _RB_JOB_CLASS_RE.match(line)
                if match:
                    end = next((offset for offset in range(index + 1, len(lines)) if lines[offset].rstrip() == line[: len(line) - len(line.lstrip())] + "end"), len(lines) - 1)
                    out.append(Consumer(_key("task", match.group(1), constants), source.rel, match.group(1), index, end))
        if suffix == ".php":
            for index, line in enumerate(lines):
                match = _PHP_QUEUED_CLASS_RE.match(line)
                if match:
                    out.append(Consumer(_key("task", match.group(1), constants), source.rel, match.group(1), index, _block_end(lines, index)))
                handle = _PHP_HANDLE_RE.search(line)
                if handle and handle.group(1) not in {"Request", "Closure"}:
                    function = next((f for f in source.functions if f.start == index), None)
                    end = function.end if function else _block_end(lines, index)
                    out.append(Consumer(_key("event", handle.group(1), constants), source.rel, "handle", index, end))
    return out


def find_producers(source: "_SourceFile", constants: Dict[str, str]) -> List[Producer]:
    out: List[Producer] = []
    seen = set()

    def add(channel: str, index: int) -> None:
        if (channel, index) not in seen:
            seen.add((channel, index))
            out.append(Producer(channel, source.rel, index))

    # BullMQ / Bee: `const sms = new Queue("sms")` then `sms.add(jobName, data)` publishes to "sms".
    queues = {m.group(1): m.group(2) for m in _QUEUE_VAR_RE.finditer("\n".join(source.lines))}
    for index, line in enumerate(source.lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "#", "*", "/*", "import ", "from ")) and not stripped.startswith("#["):
            continue
        for match in _QUEUE_ADD_RE.finditer(line):
            if match.group(1) in queues:
                add(_key("topic", queues[match.group(1)], constants, literal=True), index)
        for match in _TASK_CALL_RE.finditer(line):
            add(_key("task", match.group(1), constants), index)
        for match in _ENQUEUE_FUNC_RE.finditer(line):
            add(_key("task", match.group(1), constants), index)
            add(f"callable:{match.group(1).split('.')[-1].lower()}", index)
        for match in _SEND_TASK_RE.finditer(line):
            add(_key("task", match.group(1), constants), index)
            add(f"callable:{match.group(1).split('.')[-1].lower()}", index)
        for match in _NEW_EVENT_RE.finditer(line):
            add(_key("event", match.group(1), constants), index)
            add(_key("task", match.group(1), constants), index)  # Laravel dispatch(new Job(...))
        for match in _DJANGO_SIGNAL_SEND_RE.finditer(line):
            add(f"signal:{match.group(1).lower()}", index)
        for match in _TOPIC_CALL_RE.finditer(line):
            if match.group(2) and match.group(2).split(".")[0] in {"this", "self", "res", "response", "ws", "socket"}:
                continue
            add(_arg_key("topic", match, constants), index)
        if _TOPIC_KEY_CALLS_RE.search(line):
            statement = "\n".join(source.lines[index : index + 8])
            keyed = _TOPIC_KEY_RE.search(statement)
            if keyed:
                add(_arg_key("topic", keyed, constants), index)
    return out


def describe(channel: str) -> str:
    kind, _, value = channel.partition(":")
    return {"task": f"task `{value}`", "callable": f"task `{value}`", "event": f"event `{value}`", "signal": f"signal `{value}`", "topic-id": f"channel `{value}`"}.get(kind, f"`{value}`")

