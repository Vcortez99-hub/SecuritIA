import { api } from './api'

interface LoginRequest {
  username: string
  password: string
}

interface LoginResponse {
  access_token: string
  token_type: string
  user: {
    username: string
    role: string
    email?: string
  }
}

interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
}

class AuthService {
  async login(credentials: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    try {
      const response = await api.post('/auth/login', credentials)
      return {
        success: true,
        data: response.data
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || 'Erro no login'
      }
    }
  }

  async getCurrentUser(): Promise<ApiResponse<any>> {
    try {
      const response = await api.get('/auth/me')
      return {
        success: true,
        data: response.data
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.detail || 'Erro ao obter usuário'
      }
    }
  }

  setAuthToken(token: string) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`
  }

  removeAuthToken() {
    delete api.defaults.headers.common['Authorization']
  }
}

export const authService = new AuthService()