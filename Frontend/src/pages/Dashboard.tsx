import React from 'react';
import MainLayout from '../components/layout/MainLayout';
import AnalysisChat from '../components/Analysis/AnalysisChat';

const Dashboard: React.FC = () => {
  return (
    <MainLayout>
      <AnalysisChat />
    </MainLayout>
  );
};

export default Dashboard;