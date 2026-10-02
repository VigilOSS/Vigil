import React from 'react';
import ReactDOM from 'react-dom/client';
import './app.css';
import App from './App';
import { ToastProvider, ToastViewport } from './contexts/ToastContext';
import { applyTheme, detectInitialTheme } from './lib/theme';

// Apply the theme before the first render so the page paints in the right
// palette on cold load. Reading localStorage + matchMedia is synchronous,
// so this has no perceptible cost.
applyTheme(detectInitialTheme());

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ToastProvider>
      <App />
      <ToastViewport />
    </ToastProvider>
  </React.StrictMode>,
);
