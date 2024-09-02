import React from 'react'
import ReactDOM from 'react-dom/client'
import HomePage from './pages/HomePage.jsx'
import ErrorPage from './pages/ErrorPage.jsx'
import AnalysisPage from './pages/AnalysisPage.jsx'
import InfoPage from './pages/InfoPage.jsx'
import './index.css'

import {
  RouterProvider,
  createBrowserRouter,
} from 'react-router-dom';

const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
    errorElement: <ErrorPage />,
  },
  {
    path: '/info',
    element: <InfoPage />
  },
  {
    path: '/analysis',
    element: <AnalysisPage />
  }
])

ReactDOM.createRoot(document.getElementById('root')).render(
      <RouterProvider router={router}/>
)
