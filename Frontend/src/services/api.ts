import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor para adicionar token em todas as requisições
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor para tratar erros
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expirado ou inválido
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authService = {
  login: async (username: string, password: string) => {
    const response = await api.post('/api/login', { username, password });
    return response.data;
  },
  
  logout: async () => {
    localStorage.removeItem('authToken');
  }
};  // Certifique-se que tem este ponto e vírgula

export const scanService = {
  create: async (data: any) => {
    const response = await api.post('/api/scans', data);
    return response.data;
  },
  
  list: async () => {
    const response = await api.get('/api/scans');
    return response.data;
  },
  
  get: async (id: string) => {
    const response = await api.get(`/api/scans/${id}`);
    return response.data;
  },
};

export const vulnerabilityService = {
  list: async () => {
    const response = await api.get('/api/vulnerabilities');
    return response.data;
  },
  
  get: async (id: string) => {
    const response = await api.get(`/api/vulnerabilities/${id}`);
    return response.data;
  },
};

export const reportService = {
  list: async () => {
    const response = await api.get('/api/reports');
    return response.data;
  },
  
  download: async (id: string) => {
    const response = await api.get(`/api/reports/${id}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },
};

export default api;