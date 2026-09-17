import { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import ChatBubble from '@cloudscape-design/chat-components/chat-bubble';
import Avatar from '@cloudscape-design/chat-components/avatar';
import LoadingBar from '@cloudscape-design/chat-components/loading-bar';
import {
  Container,
  Header,
  PromptInput,
  Box,
  Button,
  Alert,
} from '@cloudscape-design/components';
import { invokeFlow, newSessionId, isConfigured } from './agentClient';
import './ChatComponent.css';

export default function ChatComponent({ user }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [sessionId, setSessionId] = useState(newSessionId);
  const endRef = useRef(null);

  const who = user?.signInDetails?.loginId ?? user?.username ?? 'You';
  const configured = isConfigured();

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const newConversation = useCallback(() => {
    setMessages([]);
    setSessionId(newSessionId());
  }, []);

  const send = async () => {
    const prompt = input.trim();
    if (!prompt || busy) return;
    setInput('');
    // Add the user's message and an empty assistant bubble to stream into.
    setMessages((m) => [...m, { role: 'user', text: prompt }, { role: 'assistant', text: '' }]);
    setBusy(true);
    try {
      await invokeFlow(prompt, sessionId, (delta) => {
        setMessages((m) => {
          const copy = m.slice();
          const last = copy[copy.length - 1];
          copy[copy.length - 1] = { ...last, text: last.text + delta };
          return copy;
        });
      });
    } catch (err) {
      setMessages((m) => {
        const copy = m.slice();
        copy[copy.length - 1] = {
          role: 'assistant',
          error: true,
          text: `Something went wrong.\n\n${String(err?.message || err)}`,
        };
        return copy;
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="chat">
      <Container
        header={
          <Header
            variant="h2"
            description="Chat with the Flow agent. Its tool calls run through the AgentCore Gateway, where Skyflow de-identifies sensitive data before it reaches the MCP servers."
            actions={
              <Button iconName="add-plus" onClick={newConversation} disabled={busy}>
                New conversation
              </Button>
            }
          >
            Flow
          </Header>
        }
      >
        {!configured && (
          <Alert type="warning" header="Console not configured">
            Set <code>VITE_FLOW_AGENT_RUNTIME_ARN</code> and <code>VITE_AGENT_REGION</code>, then rebuild.
          </Alert>
        )}

        <div className="messages">
          {messages.length === 0 && (
            <Box color="text-body-secondary" textAlign="center" padding={{ vertical: 'xl' }}>
              Ask Flow something to get started.
            </Box>
          )}

          {messages.map((m, i) => (
            <ChatBubble
              key={i}
              type={m.role === 'user' ? 'outgoing' : 'incoming'}
              ariaLabel={`${m.role === 'user' ? who : 'Flow'} message`}
              avatar={
                <Avatar
                  color={m.role === 'user' ? 'default' : 'gen-ai'}
                  ariaLabel={m.role === 'user' ? who : 'Flow'}
                  initials={m.role === 'user' ? who.slice(0, 2).toUpperCase() : 'FL'}
                />
              }
            >
              {m.text ? (
                <div className="markdown">
                  <ReactMarkdown>{m.text}</ReactMarkdown>
                </div>
              ) : (
                <LoadingBar variant="gen-ai" />
              )}
            </ChatBubble>
          ))}
          <div ref={endRef} />
        </div>

        <PromptInput
          value={input}
          onChange={({ detail }) => setInput(detail.value)}
          onAction={send}
          disabled={busy || !configured}
          placeholder="Type your message…"
          actionButtonIconName="send"
          actionButtonAriaLabel="Send message"
        />
      </Container>
    </div>
  );
}
