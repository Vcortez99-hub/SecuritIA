import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  username: string;  // ✅ Mudou de 'name' para 'username' (como backend retorna)
  email: string;
  role: string;
  active: boolean;   // ✅ Adicionado campo 'active' do backend
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  checkAuth: () => Promise<void>;
  clearError: () => void;
}

// ✅ URL corrigida para a porta correta
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (email: string, password: string) => {
        set({ isLoading: true, error: null });
        
        try {
          console.log('🔄 Tentando login...', { email });

          const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }), // ✅ Mantendo 'email' como esperado
          });

          console.log('📡 Response status:', response.status);

          if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Erro ao fazer login');
          }

          const data = await response.json();
          console.log('✅ Login response:', data);

          // ✅ Estrutura corrigida conforme resposta do backend
          set({
            user: data.user,           // Backend retorna { user: {...} }
            token: data.access_token,  // Backend retorna { access_token: "..." }
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          // ✅ Salvar token correto no localStorage
          localStorage.setItem('token', data.access_token);
          localStorage.setItem('user', JSON.stringify(data.user));
          
          console.log('🎉 Login realizado com sucesso!');
          
          // ✅ REDIRECIONAMENTO ADICIONADO
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 100);

        } catch (error) {
          console.error('❌ Login error:', error);
          set({
            error: error instanceof Error ? error.message : 'Erro ao fazer login',
            isLoading: false,
            isAuthenticated: false,
          });
          throw error; // Re-throw para componente tratar se necessário
        }
      },

      logout: () => {
        console.log('🚪 Fazendo logout...');
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
        });
        
        // Remover dados do localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        // Redirecionar para login
        window.location.href = '/login';
      },

      register: async (name: string, email: string, password: string) => {
        set({ isLoading: true, error: null });
        
        try {
          // ✅ URL corrigida (caso você implemente registro)
          const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email, password }),
          });

          if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Erro ao criar conta');
          }

          const data = await response.json();

          set({
            user: data.user,
            token: data.access_token,  // ✅ Campo correto
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          localStorage.setItem('token', data.access_token);
          localStorage.setItem('user', JSON.stringify(data.user));

          // Redirecionar após registro
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 100);

        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Erro ao criar conta',
            isLoading: false,
            isAuthenticated: false,
          });
          throw error;
        }
      },

      checkAuth: async () => {
        const token = localStorage.getItem('token');
        
        if (!token) {
          set({ isAuthenticated: false, user: null, token: null });
          return;
        }

        set({ isLoading: true });

        try {
          console.log('🔍 Verificando autenticação...');
          
          const response = await fetch(`${API_URL}/auth/me`, {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error('Token inválido');
          }

          const userData = await response.json();
          console.log('✅ Auth check successful:', userData);

          set({
            user: userData,  // /auth/me retorna os dados do usuário diretamente
            token: token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

        } catch (error) {
          console.error('❌ Auth check failed:', error);
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            isLoading: false,
          });
          
          localStorage.removeItem('token');
          localStorage.removeItem('user');
        }
      },

      clearError: () => {
        set({ error: null });
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        user: state.user, 
        token: state.token,
        isAuthenticated: state.isAuthenticated 
      }),
    }
  )
);

// Hook para usar o token em requisições
export const useAuthToken = () => {
  const token = useAuthStore((state) => state.token);
  return token;
};

// Hook para verificar se o usuário está autenticado
export const useIsAuthenticated = () => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  return isAuthenticated;
};

// Hook para obter o usuário atual
export const useCurrentUser = () => {
  const user = useAuthStore((state) => state.user);
  return user;
};