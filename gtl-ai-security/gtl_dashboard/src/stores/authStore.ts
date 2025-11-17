import { create } from 'zustand';
import { User } from '@/types';
import { login as apiLogin, logout as apiLogout, getCurrentUser } from '@/api/auth';
import { setTokens, clearTokens, getAccessToken } from '@/utils/tokenStorage';

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
  clearError: () => void;
  hasRole: (role: string) => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,

  login: async (username: string, password: string) => {
    set({ isLoading: true, error: null });
    try {
      const response = await apiLogin(username, password);
      setTokens(response.access_token, response.refresh_token);

      set({
        user: response.user,
        token: response.access_token,
        isAuthenticated: true,
        isLoading: false,
      });
    } catch (error: any) {
      set({
        error: error.response?.data?.detail || 'Login failed',
        isLoading: false,
      });
      throw error;
    }
  },

  logout: async () => {
    try {
      await apiLogout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      clearTokens();
      set({
        user: null,
        token: null,
        isAuthenticated: false,
        error: null,
      });
    }
  },

  checkAuth: async () => {
    const token = getAccessToken();
    if (!token) {
      set({ isAuthenticated: false, user: null, token: null });
      return;
    }

    set({ isLoading: true });
    try {
      const user = await getCurrentUser();
      set({
        user,
        token,
        isAuthenticated: true,
        isLoading: false,
      });
    } catch (error) {
      clearTokens();
      set({
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
      });
    }
  },

  clearError: () => set({ error: null }),

  hasRole: (role: string): boolean => {
    const { user } = get();
    if (!user) return false;
    return user.role === role || user.role === 'admin';
  },
}));
