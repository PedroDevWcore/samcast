import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { Shield, Eye, EyeOff, Lock, Mail, AlertCircle } from 'lucide-react';

const AdminLogin: React.FC = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({ email: '', senha: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));

    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {};

    if (!formData.email) {
      newErrors.email = 'Email é obrigatório';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email inválido';
    }

    if (!formData.senha) {
      newErrors.senha = 'Senha é obrigatória';
    } else if (formData.senha.length < 3) {
      newErrors.senha = 'Senha deve ter pelo menos 3 caracteres';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    setLoading(true);
    try {
      const response = await fetch('/api/admin/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('admin_token', data.token);
        localStorage.setItem('admin_data', JSON.stringify(data.admin));

        toast.success('Login realizado com sucesso!');
        navigate('/admin/dashboard');
      } else {
        toast.error(data.error || 'Erro ao fazer login');
        setErrors({ senha: data.error || 'Credenciais inválidas' });
      }
    } catch (error) {
      console.error('Login error:', error);
      toast.error('Erro de conexão. Tente novamente.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4 relative">
      {/* Fundo decorativo com SVG removido por segurança do compilador */}
      <div className="absolute inset-0 opacity-20 bg-[url('/pattern.svg')]"></div>

      <div className="relative w-full max-w-md">
        {/* Logo e Título */}
        <div className="text-center mb-8">
          <img 
            src="/logo.png" 
            alt="Logo" 
            className="h-20 mx-auto mb-4" 
          />
          <h1 className="text-3xl font-bold text-white mb-2">Painel Administrativo</h1>
          <p className="text-slate-400">Acesso restrito para administradores</p>
        </div>

        {/* Card de Login */}
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl border border-white/20 p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Campo Email */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-200 mb-2">
                Email Administrativo
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-slate-400" />
                </div>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={formData.email}
                  onChange={handleChange}
                  className={`block w-full pl-10 pr-3 py-3 border rounded-xl bg-white/5 backdrop-blur-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all ${
                    errors.email ? 'border-red-500' : 'border-white/20'
                  }`}
                  placeholder="admin@sistema.com"
                />
              </div>
              {errors.email && (
                <div className="mt-2 flex items-center text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  {errors.email}
                </div>
              )}
            </div>

            {/* Campo Senha */}
            <div>
              <label htmlFor="senha" className="block text-sm font-medium text-slate-200 mb-2">
                Senha
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-400" />
                </div>
                <input
                  id="senha"
                  name="senha"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={formData.senha}
                  onChange={handleChange}
                  className={`block w-full pl-10 pr-12 py-3 border rounded-xl bg-white/5 backdrop-blur-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all ${
                    errors.senha ? 'border-red-500' : 'border-white/20'
                  }`}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 transition-colors"
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
              {errors.senha && (
                <div className="mt-2 flex items-center text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  {errors.senha}
                </div>
              )}
            </div>

            {/* Botão de Login */}
            <button
              type="submit"
              disabled={loading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl text-sm font-medium text-white bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl"
            >
              {loading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  Entrando...
                </>
              ) : (
                <>
                  <Shield className="h-5 w-5 mr-2" />
                  Entrar no Painel
                </>
              )}
            </button>
          </form>

          {/* Informações de Segurança */}
          <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
            <div className="flex items-start">
              <AlertCircle className="h-5 w-5 text-blue-400 mr-3 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-200">
                <p className="font-medium mb-1">Acesso Seguro</p>
                <p className="text-blue-300">
                  Este painel é restrito a administradores autorizados. Todas as ações são registradas para auditoria.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Link para voltar */}
        <div className="text-center mt-6">
          <button
            onClick={() => navigate('/')}
          >
            <img 
              src="/logo.png" 
              alt="Logo" 
              className="h-20 mx-auto mb-4" 
            />
          </button>
        </div>
      </div>
    </div>
  );
};

export default AdminLogin;
