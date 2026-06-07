import Keycloak from 'keycloak-js'

// Public PKCE client in the Agents realm (created for the Portal).
export const keycloak = new Keycloak({
  url: 'https://auth.donkeywork.dev',
  realm: 'Agents',
  clientId: 'donkeywork-vault-web',
})

export async function initAuth(): Promise<boolean> {
  return keycloak.init({
    onLoad: 'login-required',
    pkceMethod: 'S256',
    checkLoginIframe: false,
  })
}
