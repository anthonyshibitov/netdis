import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import HomePage from './pages/HomePage.jsx'
import ErrorPage from './pages/ErrorPage.jsx'
import AnalysisPage from './pages/AnalysisPage.jsx'
import './index.css'

import {
  RouterProvider,
  createBrowserRouter,
} from 'react-router-dom';
import UploadPage from './pages/UploadPage.jsx'

const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
    errorElement: <ErrorPage />,
  },
  {
    path: '/info',
    element: <h1>about</h1>
  },
  {
    path: '/analysis',
    element: <AnalysisPage />
  }
])

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RouterProvider router={router}/>
  </React.StrictMode>,
)
