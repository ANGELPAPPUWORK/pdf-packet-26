import { supabase } from '@/lib/supabaseClient'

class AuthService {
  /**
   * Create a simple hash for password using SubtleCrypto (browser-safe)
   */
  private async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Initialize admin user (creates one if doesn't exist)
   */
  async initializeAdminUser(email: string, password: string): Promise<void> {
    const { data: existingUser } = await supabase
      .from('admin_users')
      .select('id')
      .eq('email', email)
      .maybeSingle()

    if (!existingUser) {
      const passwordHash = await this.hashPassword(password)
      const { error } = await supabase
        .from('admin_users')
        .insert({
          email,
          password_hash: passwordHash,
        })

      if (error) {
        console.error('Error creating admin user:', error)
        throw error
      }
    }
  }

  /**
   * Authenticate admin user
   */
  async authenticateAdmin(email: string, password: string): Promise<boolean> {
    const { data, error } = await supabase
      .from('admin_users')
      .select('password_hash')
      .eq('email', email)
      .maybeSingle()

    if (error) {
      console.error('Error authenticating admin:', error)
      throw error
    }

    if (!data) {
      return false
    }

    const passwordHash = await this.hashPassword(password)
    return data.password_hash === passwordHash
  }

  /**
   * Get admin session from localStorage
   */
  getAdminSession(): { email: string } | null {
    const session = localStorage.getItem('adminSession')
    if (!session) return null
    try {
      return JSON.parse(session)
    } catch {
      return null
    }
  }

  /**
   * Set admin session
   */
  setAdminSession(email: string): void {
    localStorage.setItem('adminSession', JSON.stringify({ email }))
  }

  /**
   * Clear admin session
   */
  clearAdminSession(): void {
    localStorage.removeItem('adminSession')
  }

  /**
   * Check if admin is authenticated
   */
  isAuthenticated(): boolean {
    return this.getAdminSession() !== null
  }
}

export const authService = new AuthService()
