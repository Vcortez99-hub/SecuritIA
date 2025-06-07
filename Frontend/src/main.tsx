import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './app.tsx' // Note que é app.tsx com 'a' minúsculo
import './index.css' // Importando index.css, não globals.css

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)