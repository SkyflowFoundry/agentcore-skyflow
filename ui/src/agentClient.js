import { fetchAuthSession } from 'aws-amplify/auth';
import {
  BedrockAgentCoreClient,
  InvokeAgentRuntimeCommand,
} from '@aws-sdk/client-bedrock-agentcore';

const REGION = import.meta.env.VITE_AGENT_REGION;
const RUNTIME_ARN = import.meta.env.VITE_FLOW_AGENT_RUNTIME_ARN;
const QUALIFIER = import.meta.env.VITE_FLOW_AGENT_QUALIFIER || undefined;

export function isConfigured() {
  return Boolean(REGION && RUNTIME_ARN);
}

// AgentCore requires a runtime session id of at least 33 characters.
export function newSessionId() {
  const rand = () => Math.random().toString(36).slice(2);
  return `agentcore-skyflow-${Date.now()}-${rand()}-${rand()}`;
}

// Pull a text delta out of one streamed Flow event. Flow yields Strands/Bedrock
// converse events shaped like:
//   { "event": { "contentBlockDelta": { "delta": { "text": "..." } } } }
// We stay defensive about a couple of shapes so a runtime tweak does not blank
// the UI; non-text events (tool use, message start/stop) simply yield "".
function textFromEvent(obj) {
  if (typeof obj === 'string') return obj;
  if (!obj || typeof obj !== 'object') return '';
  const inner = obj.event ?? obj;
  return inner?.contentBlockDelta?.delta?.text ?? inner?.delta?.text ?? '';
}

/**
 * Invoke the Flow agent and stream its reply.
 *
 * @param {string} prompt   the user's message
 * @param {string} sessionId a stable id for the conversation (>= 33 chars)
 * @param {(delta: string) => void} onDelta called with each text chunk
 * @returns {Promise<string>} the full concatenated reply
 */
export async function invokeFlow(prompt, sessionId, onDelta) {
  if (!isConfigured()) {
    throw new Error(
      'The console is not configured. Set VITE_FLOW_AGENT_RUNTIME_ARN and VITE_AGENT_REGION.',
    );
  }

  const { credentials } = await fetchAuthSession();
  if (!credentials) {
    throw new Error('No AWS credentials from Cognito — please sign in again.');
  }

  const client = new BedrockAgentCoreClient({ region: REGION, credentials });
  const response = await client.send(
    new InvokeAgentRuntimeCommand({
      agentRuntimeArn: RUNTIME_ARN,
      qualifier: QUALIFIER,
      runtimeSessionId: sessionId,
      contentType: 'application/json',
      payload: JSON.stringify({ prompt }),
    }),
  );

  let full = '';
  const emit = (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    // Tolerate both SSE ("data: {...}") and newline-delimited JSON.
    const payload = trimmed.startsWith('data:') ? trimmed.slice(5).trim() : trimmed;
    if (!payload || payload === '[DONE]') return;
    let text = '';
    try {
      text = textFromEvent(JSON.parse(payload));
    } catch {
      return; // keep-alive / comment / partial — ignore
    }
    if (text) {
      full += text;
      onDelta?.(text);
    }
  };

  const decoder = new TextDecoder();
  let buffer = '';
  const pump = (chunk) => {
    buffer += decoder.decode(chunk, { stream: true });
    let nl;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      emit(buffer.slice(0, nl));
      buffer = buffer.slice(nl + 1);
    }
  };

  // The SDK returns the body as a web ReadableStream (browser) or an async
  // iterable of byte chunks (other runtimes). Handle both.
  const body = response.response;
  if (body?.getReader) {
    const reader = body.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) pump(value);
    }
  } else if (body?.[Symbol.asyncIterator]) {
    for await (const chunk of body) pump(chunk);
  } else if (typeof body === 'string') {
    buffer = body;
  } else if (body) {
    pump(new Uint8Array(await new Response(body).arrayBuffer()));
  }

  if (buffer.trim()) emit(buffer); // flush a trailing, unterminated frame

  return full;
}
