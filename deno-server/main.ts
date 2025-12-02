// deno-server/main.ts
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// Session Management
interface Session {
  id: string;
  host: WebSocket;
  guests: Set<WebSocket>;
}

const sessions = new Map<string, Session>();

function generateCode(): string {
  // Generate a unique code based on timestamp and UUID, encoded in Base64
  const payload = `${Date.now()}:${crypto.randomUUID()}`;
  return btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

serve((req: Request) => {
  const upgrade = req.headers.get("upgrade") || "";
  if (upgrade.toLowerCase() != "websocket") {
    return new Response("Please use WebSocket client to connect.", { status: 200 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);

  let currentSessionId: string | null = null;
  let isHost = false;

  socket.onopen = () => {
    console.log("Client connected");
  };

  socket.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);

      switch (msg.type) {
        case "create": {
          // Client wants to host a session
          const code = generateCode();
          sessions.set(code, {
            id: code,
            host: socket,
            guests: new Set(),
          });
          currentSessionId = code;
          isHost = true;
          console.log(`Session created: ${code}`);
          socket.send(JSON.stringify({ type: "created", code }));
          break;
        }

        case "join": {
          // Client wants to join a session
          const code = msg.code;
          const session = sessions.get(code);
          if (session) {
            session.guests.add(socket);
            currentSessionId = code;
            isHost = false;
            console.log(`Client joined session: ${code}`);
            socket.send(JSON.stringify({ type: "joined", code }));
            // Notify host? Optional.
          } else {
            socket.send(JSON.stringify({ type: "error", message: "Session not found" }));
          }
          break;
        }

        case "term_data": {
          // Data sync
          // If Host sends it: It's OUTPUT from the Serial Device -> Broadcast to all Guests
          // If Guest sends it: It's INPUT from User -> Send to Host
          if (!currentSessionId) return;
          const session = sessions.get(currentSessionId);
          if (!session) return;

          if (isHost) {
            // Broadcast to all guests
            for (const guest of session.guests) {
              if (guest.readyState === WebSocket.OPEN) {
                guest.send(JSON.stringify({ type: "term_data", data: msg.data }));
              }
            }
          } else {
            // Send to host
            if (session.host.readyState === WebSocket.OPEN) {
              session.host.send(JSON.stringify({ type: "term_data", data: msg.data }));
            }
          }
          break;
        }
        
        case "ping":
            socket.send(JSON.stringify({ type: "pong" }));
            break;
      }
    } catch (err) {
      console.error("Error processing message:", err);
    }
  };

  socket.onclose = () => {
    if (currentSessionId) {
      const session = sessions.get(currentSessionId);
      if (session) {
        if (isHost) {
          // Host disconnected: Destroy session and notify guests
          console.log(`Host disconnected. Destroying session ${currentSessionId}`);
          for (const guest of session.guests) {
            if (guest.readyState === WebSocket.OPEN) {
              guest.send(JSON.stringify({ type: "error", message: "Host disconnected" }));
              guest.close();
            }
          }
          sessions.delete(currentSessionId);
        } else {
          // Guest disconnected: Remove from list
          console.log(`Guest disconnected from session ${currentSessionId}`);
          session.guests.delete(socket);
        }
      }
    }
  };

  return response;
}, { port: 8080 });

console.log("WebSocket server running on ws://localhost:8080");
