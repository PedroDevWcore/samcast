import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import {
  Users, Activity, Server, TrendingUp, Eye, Zap, HardDrive, 
  Globe, Shield, AlertTriangle, CheckCircle, Clock, BarChart3,
  UserPlus, Settings, LogOut, RefreshCw, Download, Trash2
} from 'lucide-react';

interface DashboardStats {
  usuarios: {
    total_usuarios: number;
    usuarios_ativos: number;
    usuarios_suspensos: number;
    usuarios_expirados: number;
    novos_usuarios_mes: number;
    novos_usuarios_semana: number;
    usuarios_ativos_semana: number;
  };
  transmissoes: {
    total_transmissoes: number;
    transmissoes_ativas: number;
    transmissoes_mes: number;
    transmissoes_semana: number;
    media_viewers: number;
    tempo_total_transmissao: number;
  };
  recursos: {
    espaco_total_alocado: number;
    espaco_total_usado: number;
    media_espectadores_limite: number;
    total_espectadores_limite: number;
    usuarios_espectadores_ilimitados: number;
    media_bitrate: number;
    maior_bitrate_maximo: number;
  };
  plataformas: Array<{
    plataforma_nome: string;
    codigo_plataforma: string;
    usuarios_configurados: number;
    usuarios_ativos: number;
  }>;
  usuarios_ativos: Array<{
    nome: string;
    email: string;
    id: string;
    total_transmissoes: number;
    ultima_transmissao: string;
    tempo_total: number;
    media_viewers: number;
  }>;
  crescimento_mensal: Array<{
    mes: string;
    novos_usuarios: number;
  }>;
  resumo: {
    taxa_crescimento_usuarios: number;
    utilizacao_espaco: number;
    tempo_medio_transmissao: number;
  };
}

const AdminDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [adminData, setAdminData] = useState<any>(null);

  useEffect(() => {
    // Verificar se está logado
    const token = localStorage.getItem('admin_token');
    const admin = localStorage.getItem('admin_data');
    
    if (!token || !admin) {
      navigate('/admin/login');
      return;
    }

    setAdminData(JSON.parse(admin));
    loadDashboardStats();
  }, [navigate]);

  const loadDashboardStats = async () => {
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch('/api/admin/dashboard/stats', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        setStats(data.data);
      } else {
        toast.error('Erro ao carregar estatísticas');
      }
    } catch (error) {
      console.error('Error loading stats:', error);
      toast.error('Erro de conexão');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('admin_token');
      await fetch('/api/admin/auth/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('admin_token');
      localStorage.removeItem('admin_data');
      navigate('/admin/login');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="flex items-center space-x-2">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          <span className="text-gray-600">Carregando dashboard...</span>
        </div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Erro ao carregar dados</h2>
          <button
            onClick={loadDashboardStats}
            className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700"
          >
            Tentar novamente
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <img 
                  src="/logo.png" 
                  alt="Logo" 
                  className="h-8 w-auto" 
                />
                <h1 className="text-2xl font-bold text-gray-900">Painel Administrativo</h1>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <button
                onClick={loadDashboardStats}
                className="p-2 text-gray-400 hover:text-gray-600 rounded-md hover:bg-gray-100"
                title="Atualizar dados"
              >
                <RefreshCw className="h-5 w-5" />
              </button>
              
              <div className="flex items-center space-x-3">
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900">{adminData?.nome}</p>
                  <p className="text-xs text-gray-500 capitalize">{adminData?.nivel_acesso?.replace('_', ' ')}</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 text-gray-400 hover:text-red-600 rounded-md hover:bg-gray-100"
                  title="Sair"
                >
                  <LogOut className="h-5 w-5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Navigation Tabs */}
        <div className="mb-8">
          <nav className="flex space-x-8">
            <button className="border-b-2 border-primary-600 text-primary-600 py-2 px-1 text-sm font-medium">
              Dashboard
            </button>
            <button
              onClick={() => navigate('/admin/users')}
              className="border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 py-2 px-1 text-sm font-medium"
            >
              Usuários
            </button>
            <button
              onClick={() => navigate('/admin/system')}
              className="border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 py-2 px-1 text-sm font-medium"
            >
              Sistema
            </button>
          </nav>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total de Usuários */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center">
              <div className="p-3 bg-blue-100 rounded-lg">
                <Users className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total de Usuários</p>
                <p className="text-2xl font-bold text-gray-900">{stats.usuarios.total_usuarios}</p>
                <p className="text-xs text-green-600">
                  +{stats.usuarios.novos_usuarios_semana} esta semana
                </p>
              </div>
            </div>
          </div>

          {/* Usuários Ativos */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center">
              <div className="p-3 bg-green-100 rounded-lg">
                <CheckCircle className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Usuários Ativos</p>
                <p className="text-2xl font-bold text-gray-900">{stats.usuarios.usuarios_ativos}</p>
                <p className="text-xs text-gray-500">
                  {((stats.usuarios.usuarios_ativos / stats.usuarios.total_usuarios) * 100).toFixed(1)}% do total
                </p>
              </div>
            </div>
          </div>

          {/* Transmissões Ativas */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center">
              <div className="p-3 bg-red-100 rounded-lg">
                <Activity className="h-6 w-6 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Transmissões Ativas</p>
                <p className="text-2xl font-bold text-gray-900">{stats.transmissoes.transmissoes_ativas}</p>
                <p className="text-xs text-gray-500">
                  {stats.transmissoes.transmissoes_semana} esta semana
                </p>
              </div>
            </div>
          </div>

          {/* Uso de Espaço */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center">
              <div className="p-3 bg-purple-100 rounded-lg">
                <HardDrive className="h-6 w-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Uso de Espaço</p>
                <p className="text-2xl font-bold text-gray-900">{stats.resumo.utilizacao_espaco}%</p>
                <p className="text-xs text-gray-500">
                  {formatBytes(stats.recursos.espaco_total_usado * 1024 * 1024)} usado
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Charts and Tables */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Crescimento de Usuários */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Crescimento de Usuários</h3>
              <TrendingUp className="h-5 w-5 text-green-600" />
            </div>
            <div className="space-y-3">
              {stats.crescimento_mensal.slice(-6).map((item, index) => (
                <div key={index} className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">{item.mes}</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-green-600 h-2 rounded-full"
                        style={{ 
                          width: `${Math.min((item.novos_usuarios / Math.max(...stats.crescimento_mensal.map(m => m.novos_usuarios))) * 100, 100)}%` 
                        }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">{item.novos_usuarios}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Plataformas Mais Usadas */}
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Plataformas Mais Usadas</h3>
              <Globe className="h-5 w-5 text-blue-600" />
            </div>
            <div className="space-y-3">
              {stats.plataformas.slice(0, 5).map((plataforma, index) => (
                <div key={index} className="flex items-center justify-between">
                  <span className="text-sm text-gray-600 capitalize">{plataforma.plataforma_nome}</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ 
                          width: `${Math.min((plataforma.usuarios_configurados / Math.max(...stats.plataformas.map(p => p.usuarios_configurados))) * 100, 100)}%` 
                        }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">{plataforma.usuarios_configurados}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Usuários Mais Ativos */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900">Usuários Mais Ativos</h3>
              <button
                onClick={() => navigate('/admin/users')}
                className="text-primary-600 hover:text-primary-700 text-sm font-medium"
              >
                Ver todos →
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Usuário
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Transmissões
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Média de Viewers
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Tempo Total
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Última Transmissão
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {stats.usuarios_ativos.slice(0, 5).map((usuario, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{usuario.nome}</div>
                        <div className="text-sm text-gray-500">{usuario.email}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {usuario.total_transmissoes}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {Math.round(usuario.media_viewers)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {formatDuration(usuario.tempo_total)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(usuario.ultima_transmissao).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
          <button
            onClick={() => navigate('/admin/users/new')}
            className="p-6 bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow text-left"
          >
            <div className="flex items-center">
              <div className="p-3 bg-green-100 rounded-lg">
                <UserPlus className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-4">
                <h4 className="text-lg font-medium text-gray-900">Criar Usuário</h4>
                <p className="text-sm text-gray-500">Adicionar novo usuário ao sistema</p>
              </div>
            </div>
          </button>

          <button
            onClick={() => navigate('/admin/system')}
            className="p-6 bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow text-left"
          >
            <div className="flex items-center">
              <div className="p-3 bg-blue-100 rounded-lg">
                <Settings className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <h4 className="text-lg font-medium text-gray-900">Configurações</h4>
                <p className="text-sm text-gray-500">Gerenciar configurações do sistema</p>
              </div>
            </div>
          </button>

          <button
            onClick={() => navigate('/admin/reports')}
            className="p-6 bg-white rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow text-left"
          >
            <div className="flex items-center">
              <div className="p-3 bg-purple-100 rounded-lg">
                <BarChart3 className="h-6 w-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <h4 className="text-lg font-medium text-gray-900">Relatórios</h4>
                <p className="text-sm text-gray-500">Visualizar relatórios detalhados</p>
              </div>
            </div>
          </button>
        </div>
      </main>
    </div>
  );
};

export default AdminDashboard;