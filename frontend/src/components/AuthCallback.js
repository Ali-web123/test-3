import React, { useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate, useSearchParams } from 'react-router-dom';

const AuthCallback = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const token = searchParams.get('token');
    const error = searchParams.get('message');
    
    if (token) {
      login(token);
      navigate('/profile');
    } else if (error) {
      console.error('Authentication error:', error);
      navigate('/');
    } else {
      navigate('/');
    }
  }, [searchParams, login, navigate]);

  return (
    <div className="min-h-screen bg-black flex items-center justify-center">
      <div className="glass-card p-8 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white mx-auto mb-4"></div>
        <p className="text-white text-lg">Processing authentication...</p>
      </div>
    </div>
  );
};

export default AuthCallback;