# Phi ChatGPT ↔ Browsallax Relay

**Contract:** `PV-CBR-RELAY-0.1`

This is a transport-only Netlify relay for the local Browsallax `PV-CBR-0.1` bridge.

```text
ChatGPT connector
      ↓ HTTPS
Netlify relay + short-lived Blob queue
      ↑ outbound polling
local Browsallax relay agent
      ↓
PV-CBR-0.1
      ↓
Vessie
```

The user's PC opens no inbound port.

## Environment variables

Set two separate secrets on the Netlify project:

- `PHI_CONNECTOR_TOKEN` — used only by the ChatGPT connector.
- `PHI_AGENT_TOKEN` — used only by the local outbound relay agent.

Use independent random values of at least 32 characters.

Neither token is the local Browsallax Operator token.

## Queue behavior

- Four allowed semantic operations only: `bridge.status`, `vessie.observe`, `vessie.ask`, `vessie.resume`.
- Requests expire after 10 minutes.
- Agent claims expire after four minutes and may be reclaimed.
- Connector status never exposes request payloads or agent claim tokens.
- Results are stored only long enough for the connector to retrieve them; an hourly cleanup removes stale records.
- v0.1 assumes one local agent for one relay project. Multi-agent atomic claiming is intentionally not claimed because Netlify Blobs has no compare-and-swap primitive.

## Local development

```bash
cd relay
npm install
npm test
npx netlify dev
```

## Deployment

The dedicated Netlify project is `phi-browsallax-relay` at `https://phi-browsallax-relay.netlify.app`. Deploy `relay/` to that project and keep both secret environment variables configured.

The relay does not grant Browsallax authority and cannot activate the user's five-minute interactive grant.
