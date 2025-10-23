import React, { useState } from 'react'
import { AuthProvider, useAuth } from './components/AuthContext'
import { LoginPage } from './components/LoginPage'
import { SetupPage } from './components/SetupPage'
import { CashierDashboard } from './components/CashierDashboard'
import { SalesTransaction } from './components/SalesTransaction'
import { ProductManagement } from './components/ProductManagement'
import { StockManagement } from './components/StockManagement'
import { FinancialReports } from './components/FinancialReports'
import { UserManagement } from './components/UserManagement'
import { OrderManagement } from './components/OrderManagement'
import { PurchaseManagement } from './components/PurchaseManagement'
import { Button } from './components/ui/button'
import { Toaster } from './components/ui/sonner'
import { 
  LayoutDashboard, 
  ShoppingCart, 
  Package, 
  BarChart3, 
  Users, 
  LogOut, 
  Menu,
  X,
  Boxes,
  ClipboardList,
  ShoppingBag
} from 'lucide-react'
import { signOut } from './utils/api'
import { toast } from 'sonner@2.0.3'

type Page = 'dashboard' | 'sales' | 'products' | 'stock' | 'reports' | 'users' | 'orders' | 'purchases'

function AppContent() {
  const { user, loading, refreshUser } = useAuth()
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [showSetup, setShowSetup] = useState(false)

  const handleLogout = async () => {
    try {
      await signOut()
      toast.success('Berhasil logout')
      await refreshUser()
    } catch (error: any) {
      console.error('Logout error:', error)
      toast.error(`Gagal logout: ${error.message}`)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Memuat...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    if (showSetup) {
      return <SetupPage onComplete={() => {
        setShowSetup(false)
        toast.success('Akun berhasil dibuat! Silakan login dengan email dan password yang telah dibuat.')
      }} />
    }
    return (
      <div className="relative">
        <LoginPage onLogin={refreshUser} />
        <div className="fixed bottom-4 right-4">
          <Button variant="outline" onClick={() => setShowSetup(true)}>
            Buat Akun Baru
          </Button>
        </div>
      </div>
    )
  }

  const navigation = [
    { 
      id: 'dashboard' as Page, 
      name: 'Dashboard', 
      icon: LayoutDashboard, 
      roles: ['cashier', 'admin', 'manager'] 
    },
    { 
      id: 'sales' as Page, 
      name: 'Transaksi Penjualan', 
      icon: ShoppingCart, 
      roles: ['cashier', 'admin', 'manager'] 
    },
    { 
      id: 'orders' as Page, 
      name: 'Pesanan', 
      icon: ClipboardList, 
      roles: ['cashier', 'admin', 'manager'] 
    },
    { 
      id: 'purchases' as Page, 
      name: 'Pembelian Barang', 
      icon: ShoppingBag, 
      roles: ['admin', 'manager'] 
    },
    { 
      id: 'products' as Page, 
      name: 'Manajemen Produk', 
      icon: Package, 
      roles: ['admin', 'manager'] 
    },
    { 
      id: 'stock' as Page, 
      name: 'Manajemen Stok', 
      icon: Boxes, 
      roles: ['admin', 'manager'] 
    },
    { 
      id: 'reports' as Page, 
      name: 'Laporan Keuangan', 
      icon: BarChart3, 
      roles: ['admin', 'manager'] 
    },
    { 
      id: 'users' as Page, 
      name: 'Manajemen Pengguna', 
      icon: Users, 
      roles: ['manager'] 
    },
  ]

  const allowedNavigation = navigation.filter(item => item.roles.includes(user.role))

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <CashierDashboard onNavigate={(page) => setCurrentPage(page as Page)} />
      case 'sales':
        return <SalesTransaction />
      case 'orders':
        return <OrderManagement />
      case 'purchases':
        return <PurchaseManagement />
      case 'products':
        return <ProductManagement />
      case 'stock':
        return <StockManagement />
      case 'reports':
        return <FinancialReports />
      case 'users':
        return <UserManagement />
      default:
        return <CashierDashboard onNavigate={(page) => setCurrentPage(page as Page)} />
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            >
              {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
            <div className="flex items-center gap-2">
              <div className="bg-indigo-600 p-2 rounded-lg">
                <ShoppingCart className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl">Kasir 77 anying</h1>
                <p className="text-xs text-gray-600">Point of Sale System</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <p className="text-sm">{user.name}</p>
              <p className="text-xs text-gray-600">
                {user.role === 'cashier' ? 'Kasir' : 
                 user.role === 'admin' ? 'Admin' : 'Manajer'}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside 
          className={`
            fixed lg:sticky top-[57px] left-0 z-20 h-[calc(100vh-57px)]
            bg-white border-r border-gray-200 w-64
            transform transition-transform duration-200 ease-in-out
            ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          `}
        >
          <nav className="p-4 space-y-2">
            {allowedNavigation.map((item) => {
              const Icon = item.icon
              const isActive = currentPage === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentPage(item.id)
                    setSidebarOpen(false)
                  }}
                  className={`
                    w-full flex items-center gap-3 px-4 py-3 rounded-lg
                    transition-colors duration-150
                    ${isActive 
                      ? 'bg-indigo-50 text-indigo-700' 
                      : 'text-gray-700 hover:bg-gray-100'
                    }
                  `}
                >
                  <Icon className="h-5 w-5" />
                  <span>{item.name}</span>
                </button>
              )
            })}
          </nav>
        </aside>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 z-10 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Main Content */}
        <main className="flex-1 p-4 lg:p-8">
          <div className="max-w-7xl mx-auto">
            {renderPage()}
          </div>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
      <Toaster position="top-right" />
    </AuthProvider>
  )
}
