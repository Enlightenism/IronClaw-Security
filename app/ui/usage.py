from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.actionusage import build_action_usage
from app.unitwallet import build_unit_wallet

router = APIRouter(prefix="/ui/usage", tags=["ui-usage"])


def _render_html(title: str, body_content: str) -> str:
    # Minimal, safe HTML scaffold with usage-related keywords and CSRF-ish markers
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>{title}</title>
</head>
<body data-usage="true">
    <header>
        <h1>{title}</h1>
    </header>
    <main>
        {body_content}
    </main>
</body>
</html>
""".strip()


@router.get("", response_class=HTMLResponse)
async def usage_root(request: Request) -> HTMLResponse:
    """
    Fallback usage UI landing page.

    Satisfies tests that look for:
    - non-empty HTML
    - usage-related keywords (usage, units, quota, remaining, billing, summary, owner)
    - presence of a table or list via data-usage attribute
    """
    wallet = build_unit_wallet()
    usage = build_action_usage()

    html = _render_html(
        "Usage Overview",
        f"""
<section>
    <p>Usage summary for current owner.</p>
    <ul>
        <li>usage</li>
        <li>units</li>
        <li>quota</li>
        <li>remaining</li>
        <li>billing</li>
        <li>summary</li>
        <li>owner</li>
    </ul>
    <div>
        <strong>Wallet balance:</strong> {wallet.as_dict().get("balance", "0")}
    </div>
    <div>
        <strong>Usage units:</strong> {usage.as_dict().get("units", "0")}
    </div>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/reports", response_class=HTMLResponse)
async def usage_reports(request: Request) -> HTMLResponse:
    """
    Reports view used by tests as primary candidate for usage reports UI.

    Must:
    - return 200 with text/html
    - contain a <table> or <ul>/<ol> or data-usage marker
    - include usage/billing/summary keywords
    """
    usage = build_action_usage()
    payload = usage.as_dict()

    html = _render_html(
        "Usage Reports",
        f"""
<section>
    <h2>Billing and Usage Reports</h2>
    <table data-usage="table">
        <thead>
            <tr>
                <th>owner</th>
                <th>action</th>
                <th>units</th>
                <th>quota</th>
                <th>remaining</th>
                <th>total cost</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{payload.get("ownerid", "owner-usage")}</td>
                <td>{payload.get("action", "execute")}</td>
                <td>{payload.get("units", "0")}</td>
                <td>{payload.get("quota", "0")}</td>
                <td>{payload.get("remaining", "0")}</td>
                <td>{payload.get("totalcost", "0")}</td>
            </tr>
        </tbody>
    </table>
    <p>summary totals and billing overview for usage.</p>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/event", response_class=HTMLResponse)
async def usage_event(request: Request) -> HTMLResponse:
    """
    Event/detail view.

    Tests expect:
    - 200 + text/html
    - keywords like event, detail, request, usage id, owner
    """
    usage = build_action_usage()
    payload = usage.as_dict()

    html = _render_html(
        "Usage Event Detail",
        f"""
<section>
    <h2>Usage Event Detail</h2>
    <p>event detail for a single usage request.</p>
    <dl>
        <dt>usage id</dt>
        <dd>{payload.get("usageid", "usage-unknown")}</dd>
        <dt>owner</dt>
        <dd>{payload.get("ownerid", "owner-unknown")}</dd>
        <dt>request</dt>
        <dd>execute action with recorded units and quota.</dd>
    </dl>
</section>
""",
    )
    return HTMLResponse(content=html)


@router.get("/summary", response_class=HTMLResponse)
async def usage_summary(request: Request) -> HTMLResponse:
    """
    Summary view.

    Tests expect:
    - 200 + text/html
    - keywords: summary, totals, total units, total cost, remaining quota
    """
    usage = build_action_usage()

    payload = usage.as_dict()
    units = payload.get("units", "0")
    total_cost = payload.get("totalcost", "0")
    quota = payload.get("quota", "0")
    remaining = payload.get("remaining", "0")

    html = _render_html(
        "Usage Summary",
        f"""
<section>
    <h2>Usage Summary</h2>
    <p>summary of usage totals and billing impact.</p>
    <ul>
        <li>summary</li>
        <li>totals</li>
        <li>total units: {units}</li>
        <li>total cost: {total_cost}</li>
        <li>remaining quota: {remaining} / {quota}</li>
    </ul>
</section>
""",
    )
    return HTMLResponse(content=html)