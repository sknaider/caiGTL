import { useEffect, useRef, useState, useCallback } from 'react';
import { ScanProgress } from '@/types';
import { getAccessToken } from '@/utils/tokenStorage';

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

interface UseWebSocketOptions {
  onMessage?: (data: ScanProgress) => void;
  onError?: (error: Event) => void;
  onClose?: () => void;
  reconnect?: boolean;
  reconnectInterval?: number;
}

export const useWebSocket = (
  scanId: string | null,
  options: UseWebSocketOptions = {}
) => {
  const {
    onMessage,
    onError,
    onClose,
    reconnect = true,
    reconnectInterval = 3000,
  } = options;

  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (!scanId) return;

    const token = getAccessToken();
    if (!token) {
      setError('No authentication token');
      return;
    }

    try {
      const wsUrl = `${WS_BASE_URL}/ws/scans/${scanId}?token=${token}`;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected for scan:', scanId);
        setConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data: ScanProgress = JSON.parse(event.data);
          setProgress(data);
          onMessage?.(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onerror = (event) => {
        console.error('WebSocket error:', event);
        setError('WebSocket connection error');
        onError?.(event);
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setConnected(false);
        wsRef.current = null;
        onClose?.();

        // Attempt reconnection
        if (
          reconnect &&
          reconnectAttemptsRef.current < maxReconnectAttempts
        ) {
          reconnectAttemptsRef.current += 1;
          console.log(
            `Reconnecting... (attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts})`
          );
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      wsRef.current = ws;
    } catch (err) {
      console.error('Failed to create WebSocket:', err);
      setError('Failed to create WebSocket connection');
    }
  }, [scanId, onMessage, onError, onClose, reconnect, reconnectInterval]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    setProgress(null);
  }, []);

  useEffect(() => {
    if (scanId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [scanId, connect, disconnect]);

  return {
    progress,
    connected,
    error,
    disconnect,
    reconnect: connect,
  };
};
