import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, 
  Shield, 
  FileText, 
  Eye, 
  Settings, 
  User,
  X,
  Activity,
  AlertTriangle
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import clsx from 'clsx'

interface SidebarProps {
  isOpen: boolean
  onClose: () => void
}

const navigationItems = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    name: 'Scans',
    href: '/scans',
    icon: Shield,
  },
  {
    name: 'Relatórios',
    href: '/reports',
    icon: FileText,
  },
  {
    name: 'Dark Web',
    href: '/dark-web',
    icon: Eye,
  },
  {
    name: 'Configurações',
    href: '/settings',
    icon: Settings,
  },
  {
    name: 'Perfil',
    href: '/profile',
    icon: User,
  }
]

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const location = useLocation()

  return (
    <>
      {/* Mobile overlay */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-20 bg-black bg-opacity-50 lg:hidden"
            onClick={onClose}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{
          x: isOpen ? 0 : '-100%',
        }}
        transition={{
          type: 'spring',
          stiffness: 300,
          damping: 30,
        }}
        className={clsx(
          'fixed inset-y-0 left-0 z-30 w-64 bg-gray-900 text-white transform lg:translate-x-0 lg:static lg:inset-0',
          'lg:block'
        )}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-between h-16 px-6 border-b border-gray-700">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5" />
              </div>
              <span className="text-xl font-bold">SECURIT IA</span>
            </div>
            
            {/* Close button (mobile only) */}
            <button
              onClick={onClose}
              className="lg:hidden p-1 rounded-md hover:bg-gray-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2">
            {navigationItems.map((item) => {
              const isActive = location.pathname === item.href || 
                             location.pathname.startsWith(item.href + '/')
              
              return (
                <NavLink
                  key={item.name}
                  to={item.href}
                  onClick={() => onClose()}
                  className={({ isActive: linkActive }) =>
                    clsx(
                      'flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors duration-200',
                      (isActive || linkActive)
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                    )
                  }
                >
                  <item.icon className="w-5 h-5" />
                  <span className="font-medium">{item.name}</span>
                </NavLink>
              )
            })}
          </nav>

          {/* Status indicator */}
          <div className="px-4 py-4 border-t border-gray-700">
            <div className="flex items-center space-x-3 px-3 py-2 bg-gray-800 rounded-lg">
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-300">
                  Sistema Online
                </p>
                <p className="text-xs text-gray-500">
                  Todos os serviços ativos
                </p>
              </div>
            </div>
          </div>
        </div>
      </motion.aside>
    </>
  )
}

export default Sidebar