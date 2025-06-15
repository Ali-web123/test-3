import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

const ProfilePage = () => {
  const { user, logout, updateProfile } = useAuth();
  const navigate = useNavigate();
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    name: user?.name || '',
    about_me: user?.about_me || '',
    age: user?.age || ''
  });
  const [saving, setSaving] = useState(false);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSaveProfile = async () => {
    setSaving(true);
    try {
      const profileUpdate = {
        ...formData,
        age: formData.age ? parseInt(formData.age) : null
      };
      await updateProfile(profileUpdate);
      setIsEditing(false);
    } catch (error) {
      console.error('Failed to update profile:', error);
      alert('Failed to update profile. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleCancelEdit = () => {
    setFormData({
      name: user?.name || '',
      about_me: user?.about_me || '',
      age: user?.age || ''
    });
    setIsEditing(false);
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="glass-card p-8 text-center">
          <p className="text-white">Loading profile...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black px-6 py-20">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <button
            onClick={() => navigate('/')}
            className="glass-button inline-flex items-center"
          >
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
            </svg>
            Back to Courses
          </button>
          
          <button
            onClick={handleLogout}
            className="glass-button bg-red-500/20 border-red-400 text-red-300 hover:bg-red-500/30"
          >
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
            </svg>
            Logout
          </button>
        </div>

        {/* Profile Card */}
        <div className="glass-card p-8">
          <div className="flex flex-col md:flex-row items-start gap-8">
            {/* Profile Picture */}
            <div className="flex-shrink-0">
              <img
                src={user.picture || 'https://via.placeholder.com/150?text=Profile'}
                alt="Profile"
                className="w-32 h-32 rounded-full border-4 border-white/20"
              />
            </div>

            {/* Profile Information */}
            <div className="flex-1 w-full">
              <div className="flex justify-between items-start mb-6">
                <h1 className="text-3xl font-bold text-white">My Profile</h1>
                {!isEditing ? (
                  <button
                    onClick={() => setIsEditing(true)}
                    className="glass-button bg-blue-500/20 border-blue-400 text-blue-300 hover:bg-blue-500/30"
                  >
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                    </svg>
                    Edit Profile
                  </button>
                ) : (
                  <div className="flex gap-2">
                    <button
                      onClick={handleSaveProfile}
                      disabled={saving}
                      className="glass-button bg-green-500/20 border-green-400 text-green-300 hover:bg-green-500/30 disabled:opacity-50"
                    >
                      {saving ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                          Saving...
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7"/>
                          </svg>
                          Save
                        </>
                      )}
                    </button>
                    <button
                      onClick={handleCancelEdit}
                      disabled={saving}
                      className="glass-button bg-gray-500/20 border-gray-400 text-gray-300 hover:bg-gray-500/30 disabled:opacity-50"
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>

              <div className="grid gap-6">
                {/* Name */}
                <div>
                  <label className="block text-white font-semibold mb-2">Name</label>
                  {isEditing ? (
                    <input
                      type="text"
                      name="name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-white/40"
                      placeholder="Enter your name"
                    />
                  ) : (
                    <p className="text-gray-300 text-lg">{user.name}</p>
                  )}
                </div>

                {/* Email (read-only) */}
                <div>
                  <label className="block text-white font-semibold mb-2">Email</label>
                  <p className="text-gray-300 text-lg">{user.email}</p>
                  <p className="text-gray-500 text-sm">Email cannot be changed</p>
                </div>

                {/* Age */}
                <div>
                  <label className="block text-white font-semibold mb-2">Age</label>
                  {isEditing ? (
                    <input
                      type="number"
                      name="age"
                      value={formData.age}
                      onChange={handleInputChange}
                      className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-white/40"
                      placeholder="Enter your age"
                      min="13"
                      max="120"
                    />
                  ) : (
                    <p className="text-gray-300 text-lg">{user.age || 'Not specified'}</p>
                  )}
                </div>

                {/* About Me */}
                <div>
                  <label className="block text-white font-semibold mb-2">About Me</label>
                  {isEditing ? (
                    <textarea
                      name="about_me"
                      value={formData.about_me}
                      onChange={handleInputChange}
                      rows={4}
                      className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-white/40 resize-vertical"
                      placeholder="Tell us about yourself..."
                    />
                  ) : (
                    <p className="text-gray-300 text-lg whitespace-pre-wrap">
                      {user.about_me || 'No description provided yet.'}
                    </p>
                  )}
                </div>

                {/* Account Information */}
                <div className="pt-6 border-t border-white/10">
                  <h3 className="text-white font-semibold mb-4">Account Information</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Member since:</span>
                      <p className="text-gray-300">
                        {new Date(user.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <span className="text-gray-400">Last login:</span>
                      <p className="text-gray-300">
                        {new Date(user.last_login).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;