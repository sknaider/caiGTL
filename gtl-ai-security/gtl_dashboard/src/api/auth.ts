import apiClient from './client';
import { LoginRequest, LoginResponse, RefreshTokenResponse, User } from '@/types';

export const login = async (username: string, password: string): Promise<LoginResponse> => {
  const response = await apiClient.post<LoginResponse>('/auth/login', {
    username,
    password,
  });
  return response.data;
};

export const logout = async (): Promise<void> => {
  try {
    await apiClient.post('/auth/logout');
  } catch (error) {
    console.error('Logout error:', error);
  }
};

export const refreshToken = async (refreshToken: string): Promise<RefreshTokenResponse> => {
  const response = await apiClient.post<RefreshTokenResponse>('/auth/refresh', {
    refresh_token: refreshToken,
  });
  return response.data;
};

export const getCurrentUser = async (): Promise<User> => {
  const response = await apiClient.get<User>('/auth/me');
  return response.data;
};

export const changePassword = async (
  currentPassword: string,
  newPassword: string
): Promise<void> => {
  await apiClient.post('/auth/change-password', {
    current_password: currentPassword,
    new_password: newPassword,
  });
};
