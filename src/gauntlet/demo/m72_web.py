"""Trusted localhost controller and browser shell for M7.2 live execution."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from gauntlet.demo.m72 import M72LiveOrchestrator, safe_live_message


ProviderFactory = Callable[[], object]


def render_live_page() -> str:
    return _LIVE_HTML


def create_live_demo_app(repository_root: Path, provider_factory: ProviderFactory,
                         *, evidence_directory: Path | None = None) -> FastAPI:
    root = repository_root.resolve(strict=True)
    evidence_root = evidence_directory or root / "evidence/m7-live"
    states: dict[str, dict[str, object]] = {}
    app = FastAPI(title="Gauntlet M7.2 local demo")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return render_live_page()

    @app.get("/verified-replay")
    async def replay() -> FileResponse:
        path = root / "demo/gauntlet-m7.html"
        if not path.is_file():
            raise HTTPException(404, "Build the offline M7.1 replay first")
        return FileResponse(path, media_type="text/html")

    async def execute(run_id: str) -> None:
        state = states[run_id]

        def update(stage: str, status: str, details: dict[str, object]) -> None:
            state["stages"][stage] = {"status": status, **details}  # type: ignore[index]

        try:
            provider = provider_factory()
            evidence_path = evidence_root / f"{run_id}.json"
            result = await M72LiveOrchestrator(root, provider).run(
                evidence_path=evidence_path, on_stage=update,
            )
            state.update({
                "status": "COMPLETE", "verdict": result.final_verdict,
                "evidence_path": evidence_path.relative_to(root).as_posix()
                if evidence_path.is_relative_to(root) else evidence_path.name,
                "patch": result.patch,
                "patch_digest": result.patch_digest,
                "failure_stage": result.failure_stage,
                "failure_message": result.failure_message,
                "provider_requests": result.provider_request_count,
            })
        except Exception as exc:
            state.update({
                "status": "COMPLETE", "verdict": "NOT_VERIFIED",
                "failure_stage": "STARTUP",
                "failure_message": safe_live_message(exc), "provider_requests": 0,
            })

    @app.post("/api/live-runs", status_code=202)
    async def start_run() -> dict[str, str]:
        if any(item.get("status") == "RUNNING" for item in states.values()):
            raise HTTPException(409, "A live Gauntlet run is already active")
        run_id = str(uuid4())
        states[run_id] = {"run_id": run_id, "status": "RUNNING", "stages": {}}
        asyncio.create_task(execute(run_id))
        return {"run_id": run_id}

    @app.get("/api/live-runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, object]:
        if run_id not in states:
            raise HTTPException(404, "Unknown live run")
        return states[run_id]

    return app


_LIVE_HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Gauntlet Live Run</title>
<style>:root{--bg:#080b0f;--panel:#111820;--line:#293542;--text:#edf4f7;--muted:#8b9aaa;--cyan:#54e7ff;--green:#62f6a7;--red:#ff6978;--amber:#ffc86b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% -20%,#193645,var(--bg) 52%);color:var(--text);font-family:system-ui,-apple-system,sans-serif;min-height:100vh}.top{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 24px}.brand{font-weight:850;letter-spacing:.12em}.live{color:var(--red);font:750 11px ui-monospace,monospace}.wrap{max-width:1100px;margin:auto;padding:42px 24px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:start}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:.18em;font-weight:800}.hero h1{font-size:clamp(34px,6vw,64px);letter-spacing:-.05em;line-height:1;margin:10px 0}.hero p{color:var(--muted);max-width:620px;line-height:1.6}.actions{display:flex;gap:10px;flex-wrap:wrap}.btn{border:1px solid var(--cyan);border-radius:8px;padding:13px 16px;background:var(--cyan);color:#071015;font-weight:850;cursor:pointer;text-decoration:none;font-size:12px}.btn.secondary{background:transparent;color:var(--cyan)}.meta{display:flex;gap:9px;margin:28px 0;flex-wrap:wrap}.pill{border:1px solid var(--line);border-radius:99px;padding:7px 10px;color:var(--muted);font-size:11px}.flow{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.stage{border:1px solid var(--line);background:var(--panel);padding:15px;border-radius:10px;min-height:92px}.stage b{font-size:12px;letter-spacing:.08em}.stage span{display:block;color:var(--muted);font:700 11px ui-monospace,monospace;margin-top:13px}.stage.pass{border-color:#62f6a766}.stage.pass span{color:var(--green)}.stage.fail{border-color:#ff697866}.stage.fail span{color:var(--red)}.stage.running{border-color:#54e7ff88}.stage.running span{color:var(--cyan)}.result{display:none;margin-top:24px;border:1px solid var(--line);border-radius:12px;background:#0d1319;padding:20px}.result.show{display:block}.result h2{margin:0 0 8px}.result.verified h2{color:var(--green)}.result.failed h2{color:var(--red)}pre{white-space:pre;overflow:auto;max-height:430px;border:1px solid var(--line);padding:14px;background:#080c10;color:#cbd7df;font-size:11px}.error{color:var(--amber)}@media(max-width:720px){.hero{display:block}.actions{margin-top:22px}.flow{grid-template-columns:1fr}.wrap{padding:28px 16px}}</style></head>
<body><header class="top"><div class="brand">GAUNTLET</div><div class="live">● LIVE RUN</div></header><main class="wrap"><section class="hero"><div><span class="eyebrow">REAL EXECUTION · LOCAL TRUST BOUNDARY</span><h1>AI proposes.<br>Execution proves.</h1><p>Run P100, request one Kimi repair through Nebius, then let Gauntlet validate, sandbox, re-attack, mutate, and prove the actual candidate.</p></div><div class="actions"><button class="btn" id="run">RUN LIVE GAUNTLET</button><a class="btn secondary" href="/verified-replay">VIEW VERIFIED REPLAY</a></div></section><div class="meta"><span class="pill">Provider: Nebius</span><span class="pill">Model: Kimi K2.7 Code</span><span class="pill">One provider request maximum</span></div><section class="flow" id="flow"></section><section class="result" id="result"><h2 id="verdict"></h2><p class="error" id="failure"></p><div id="patchbox" hidden><b>AI-PROPOSED REPAIR</b><pre><code id="patch"></code></pre><p>Gauntlet verification is reported separately above.</p></div><p id="receipt"></p><a class="btn secondary" href="/verified-replay">VIEW VERIFIED REPLAY</a></section></main>
<script>(()=>{'use strict';const names=['ATTACK','DIAGNOSE','AI_PATCH','VALIDATE','SANDBOX','RE_ATTACK','MUTATE','UTILITY','PROVE'],flow=document.getElementById('flow'),run=document.getElementById('run'),result=document.getElementById('result');for(const n of names){const e=document.createElement('div');e.className='stage';e.dataset.stage=n;e.innerHTML='<b>'+n.replace('_','-')+'</b><span>READY</span>';flow.appendChild(e)}function paint(stages){for(const [name,value] of Object.entries(stages||{})){const e=document.querySelector('[data-stage="'+name+'"]');if(!e)continue;e.querySelector('span').textContent=value.status;e.className='stage '+(/PASS|COMPLETE|REPRODUCED|BLOCKED|VERIFIED|RECEIVED|4\/4/.test(value.status)?'pass':/FAIL|LEAKED|ERROR|NOT_VERIFIED/.test(value.status)?'fail':'running')}}async function start(){run.disabled=true;run.textContent='LIVE RUN ACTIVE';let response;try{response=await fetch('/api/live-runs',{method:'POST'});if(!response.ok)throw new Error(await response.text());const {run_id}=await response.json();for(;;){const state=await(await fetch('/api/live-runs/'+run_id)).json();paint(state.stages);if(state.status==='COMPLETE'){result.className='result show '+(state.verdict==='VERIFIED'?'verified':'failed');document.getElementById('verdict').textContent=state.verdict==='VERIFIED'?'SECURITY REPAIR VERIFIED / PROTECTED':'REPAIR NOT VERIFIED';document.getElementById('failure').textContent=state.failure_message||'';if(state.patch){document.getElementById('patchbox').hidden=false;document.getElementById('patch').textContent=state.patch}document.getElementById('receipt').textContent='Provider requests: '+state.provider_requests+(state.evidence_path?' · Evidence: '+state.evidence_path:'');break}await new Promise(r=>setTimeout(r,350))}}catch(error){result.className='result show failed';document.getElementById('verdict').textContent='LIVE RUN UNAVAILABLE';document.getElementById('failure').textContent=String(error)}finally{run.disabled=false;run.textContent='RUN LIVE GAUNTLET'}}run.addEventListener('click',start)})();</script></body></html>'''
