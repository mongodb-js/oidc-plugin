import type { AddressInfo } from 'net';
import type { Browser, RemoteOptions } from 'webdriverio';
import { remote as webdriverIoRemote } from 'webdriverio';
import express from 'express';
import { createServer as createHTTPServer } from 'http';
import OIDCProvider from 'oidc-provider';
import type { Server as HTTPServer } from 'http';
import type { DeviceFlowInformation, OpenBrowserOptions } from '../src';

import type {
  Configuration as OIDCProviderConfiguration,
  ClientMetadata as OIDCClientMetadata,
} from 'oidc-provider';
import path from 'path';
import { once } from 'events';
import type { IdPServerInfo } from '../src';

{
  // monkey-patch the test oidc provider so that it returns 'typ: JWT'
  // tokens because the server does not accept any other value for 'typ'.
  // For testing purposes, this should not be an issue.
  // https://github.com/10gen/mongo/blob/041756701e6202ff3054106bf9ae9b966e55dbb2/src/mongo/crypto/jws_validated_token.cpp#L109
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const _JWT = require('oidc-provider/lib/helpers/jwt');
  const _sign = _JWT.sign;
  _JWT.sign = (
    payload: unknown,
    key: unknown,
    alg: unknown,
    options: Record<string, unknown> = {}
  ) => {
    if (options.typ === 'at+jwt') options = { ...options, typ: 'JWT' };
    return _sign.call(this, payload, key, alg, options);
  };
}

const oidcClientConfig: Readonly<OIDCClientMetadata> = {
  client_id: 'zELcpfANLqY7Oqas',
  grant_types: [
    'refresh_token',
    'authorization_code',
    'urn:ietf:params:oauth:grant-type:device_code',
  ],
  redirect_uris: ['http://localhost:27097/redirect'],
  application_type: 'native',
  token_endpoint_auth_method: 'none',
};

const oidcProviderConfig: Readonly<OIDCProviderConfiguration> = {
  clients: [oidcClientConfig],
  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
  claims: {
    address: ['address'],
    email: ['email', 'email_verified'],
    phone: ['phone_number', 'phone_number_verified'],
    profile: ['birthdate'],
    mongodbGroups: ['groups'],
  },
  extraTokenClaims() {
    return {
      groups: ['testgroup'], // MongoDB uses extra claims to assign roles to users
    };
  },
  cookies: {
    keys: ['asdfghjkilmnop'],
  },
  features: {
    devInteractions: { enabled: false },
    deviceFlow: { enabled: true },
    revocation: { enabled: true },
    jwtResponseModes: { enabled: true },

    resourceIndicators: {
      defaultResource: () => 'mongodb://localhost/',
      useGrantedResource: () => true,
      getResourceServerInfo: () => ({
        scope: 'api:read api:write',
        audience: 'resource-server-audience-value',
        accessTokenFormat: 'jwt',
        jwt: {
          sign: { alg: 'RS256' },
        },
      }),
    },
  },
  jwks: {
    keys: [
      // MongoDB only supports RSA keys at the time of writing
      {
        d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
        dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
        dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
        e: 'AQAB',
        kty: 'RSA',
        n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
        p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
        q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
        qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
        use: 'sig',
      },
    ],
  },
  issueRefreshToken: () => true,
};

export class OIDCTestProvider {
  public accessTokenTTLSeconds: number | undefined;
  public refreshTokenTTLSeconds: number | undefined;

  public httpServer: HTTPServer;
  private issuer: string;

  private constructor() {
    this.httpServer = createHTTPServer();
    // Initialized in .init()
    this.issuer = '';
  }

  private async init(): Promise<this> {
    this.httpServer.listen(0);
    await once(this.httpServer, 'listening');
    const { port } = this.httpServer.address() as AddressInfo;

    const app = express();
    this.httpServer.on('request', app);
    const oidcProvider = new OIDCProvider(`http://localhost:${port}`, {
      ...oidcProviderConfig,
      ttl: {
        AccessToken: () => {
          return this.accessTokenTTLSeconds ?? 3600;
        },
        RefreshToken: () => {
          return this.refreshTokenTTLSeconds ?? 3600;
        },
      },
    });

    const oidcProviderExpressExamplePath = require.resolve(
      'oidc-provider/example/routes/express'
    );
    app.set(
      'views',
      path.resolve(path.dirname(oidcProviderExpressExamplePath), '..', 'views')
    );
    app.set('view engine', 'ejs');
    (await import(oidcProviderExpressExamplePath)).default(app, oidcProvider);
    const oidcProviderAppCallback = oidcProvider.callback();
    app.use((req, res) => void oidcProviderAppCallback(req, res));

    this.issuer = `http://localhost:${port}`;
    return this;
  }

  public static async create(): Promise<OIDCTestProvider> {
    return await new this().init();
  }

  public async close(): Promise<void> {
    this.httpServer.close();
    await once(this.httpServer, 'close');
  }

  public getMongodbOIDCDBInfo(): IdPServerInfo {
    return {
      clientId: oidcClientConfig.client_id,
      issuer: this.issuer,
    };
  }
}

let canSpawnRegularBrowser = !process.env.SKIP_REGULAR_BROWSER_TESTING;
async function spawnBrowser(
  url: string,
  hideLogs?: boolean // For when real credentials are used in a flow
): Promise<Browser> {
  const options: RemoteOptions = {
    capabilities: { browserName: 'chrome' },
    waitforTimeout: 10_000,
    waitforInterval: 100,
    logLevel: hideLogs ? 'error' : 'info',
  };

  // We set ELECTRON_RUN_AS_NODE=1 for tests so that we can use
  // process.execPath to run scripts. Here, we want the actual, regular
  // electron application, though.
  const originalElectronRunAsNode = process.env.ELECTRON_RUN_AS_NODE;
  delete process.env.ELECTRON_RUN_AS_NODE;
  // nyc uses process-on-spawn to attach coverage. Electron child processes
  // fail to load it, though, so this doesn't really work; we need to hook
  // into the mechanism for injecting NODE_OPTIONS here to remove it again
  // before spawning.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let processOnSpawn: any;
  try {
    processOnSpawn = await import('process-on-spawn');
  } catch (e) {
    /* ignore */
  }
  function deleteNodeOptions({ env }: { env: Record<string, unknown> }) {
    delete env.NODE_OPTIONS;
  }
  processOnSpawn?.addListener(deleteNodeOptions);

  let browser;
  try {
    if (!canSpawnRegularBrowser) {
      throw new Error(
        'Failed to spawn regular browser in the past, skipping to Electron...'
      );
    }
    browser = await webdriverIoRemote(options);
  } catch (err: unknown) {
    canSpawnRegularBrowser = false;
    // If we cannot spawn Chromium as a regular browser, we have Electron
    // available as a dev dependency anyway and can just use it as a fallback.
    const electronPath: string = process.versions.electron
      ? process.execPath
      : ((await import('electron')).default as unknown as string);
    try {
      browser = await webdriverIoRemote({
        ...options,
        capabilities: {
          ...options.capabilities,
          'goog:chromeOptions': {
            binary: electronPath,
            args: [`--app=${url}`, '--'],
          },
        },
      });
    } catch (err2: unknown) {
      // eslint-disable-next-line no-console
      console.error('Failed to spawn browser for testing:', err);
      // eslint-disable-next-line no-console
      console.error('Failed to spawn electron for testing:', err2);
      throw err;
    }
  } finally {
    if (originalElectronRunAsNode !== undefined)
      process.env.ELECTRON_RUN_AS_NODE = originalElectronRunAsNode;
    processOnSpawn?.removeListener(deleteNodeOptions);
  }

  try {
    await browser.navigateTo(url);
  } catch (err: unknown) {
    await browser.deleteSession();
    throw err;
  }

  return browser;
}

async function dumpHtml(browser: Browser | undefined): Promise<void> {
  if (browser) {
    /* eslint-disable no-console */
    console.error('-------- Current HTML --------');
    console.error(await browser.$('body')?.getHTML());
    console.error('---- Current input values ----');
    console.error(
      Object.fromEntries(
        await browser
          .$$('input')
          .map(async (el) => [
            await el.getAttribute('name'),
            await el.getValue(),
          ])
      )
    );
    console.error('------------------------------');
    /* eslint-enable */
  }
}

async function waitForTitle(
  browser: Browser,
  expected: string | RegExp,
  selector = 'h1'
): Promise<void> {
  await browser.waitUntil(async () => {
    const actual = (await browser.$(selector).getText()).trim();
    let matches: boolean;
    if (typeof expected === 'string') {
      matches = actual.toLowerCase() === expected.toLowerCase();
    } else {
      matches = expected.test(actual);
    }

    if (!matches) {
      throw new Error(`Wanted title "${String(expected)}", saw "${actual}"`);
    }
    return true;
  });
}

async function ensureValue(
  browser: Browser,
  selector: string,
  value: string | number,
  normalize: (value: string) => string = (value) => value
): Promise<void> {
  const el = await browser.$(selector);
  await el.waitForDisplayed();
  await el.setValue(value);
  await browser.waitUntil(async () => {
    const actual = await el.getValue();
    if (normalize(String(actual)) !== normalize(String(value))) {
      await el.setValue(value); // attempt to set value again before continuing
      throw new Error(
        `Wanted value "${value}" for element "${selector}", saw "${actual}"`
      );
    }
    return true;
  });
}

async function waitForLocalhostRedirect(browser: Browser): Promise<void> {
  await browser.waitUntil(async () => {
    return /^(localhost|\[::1\]|^127\.([0-9.]+)|)$/.test(
      new URL(await browser.getUrl()).hostname
    );
  });
}

export async function functioningAuthCodeBrowserFlow({
  url,
}: OpenBrowserOptions): Promise<void> {
  let browser: Browser | undefined;
  try {
    browser = await spawnBrowser(url);
    await waitForTitle(browser, 'Sign-in');
    await ensureValue(browser, 'input[name="login"]', 'testuser');
    await ensureValue(browser, 'input[name="password"]', 'testpassword');
    await browser.$('button[type="submit"]').click();
    const idpUrl = await browser.getUrl();

    await waitForTitle(browser, 'Authorize');
    await browser.$('button[type="submit"][autofocus]').click();

    // Cannot use `waitForLocalhostRedirect` because we already started on localhost
    await browser.waitUntil(async () => {
      return (
        new URL((await browser?.getUrl()) ?? 'http://nonexistent').host !==
        new URL(idpUrl).host
      );
    });
  } catch (err: unknown) {
    await dumpHtml(browser);
    throw err;
  } finally {
    await browser?.deleteSession();
  }
}

export async function abortBrowserFlow({
  url,
}: OpenBrowserOptions): Promise<void> {
  let browser: Browser | undefined;
  try {
    browser = await spawnBrowser(url);
    await waitForTitle(browser, 'Sign-in');
    await browser.$('a[href$=abort]').click();
    await browser.$('form').waitForDisplayed({ reverse: true });
  } catch (err: unknown) {
    await dumpHtml(browser);
    throw err;
  } finally {
    await browser?.deleteSession();
  }
}

export async function functioningDeviceAuthBrowserFlow({
  verificationUrl,
  userCode,
}: DeviceFlowInformation): Promise<void> {
  let browser: Browser | undefined;
  try {
    browser = await spawnBrowser(verificationUrl);
    await waitForTitle(browser, 'Sign-in');
    await ensureValue(browser, 'input[name="user_code"]', userCode);
    await browser.$('button[type="submit"]').click();

    await waitForTitle(browser, 'Confirm Device');
    await browser.$('button[type="submit"][autofocus]').click();

    await waitForTitle(browser, 'Sign-in');
    await ensureValue(browser, 'input[name="login"]', 'testuser');
    await ensureValue(browser, 'input[name="password"]', 'testpassword');
    await browser.$('button[type="submit"]').click();

    await waitForTitle(browser, 'Authorize');
    await browser.$('button[type="submit"][autofocus]').click();
    await waitForTitle(browser, 'Sign-in Success');
  } catch (err: unknown) {
    await dumpHtml(browser);
    throw err;
  } finally {
    await browser?.deleteSession();
  }
}

interface UserPassCredentials {
  username: string;
  password: string;
}

export async function oktaBrowserAuthCodeFlow({
  username,
  password,
  url,
}: OpenBrowserOptions & UserPassCredentials): Promise<void> {
  let browser: Browser | undefined;
  try {
    browser = await spawnBrowser(url, true);
    await waitForTitle(browser, 'Sign In', 'h2');
    await ensureValue(browser, 'input[name="identifier"]', username);
    await ensureValue(browser, 'input[name="credentials.passcode"]', password);
    await browser.$('input[type="submit"]').click();
    await waitForLocalhostRedirect(browser);
  } finally {
    await browser?.deleteSession();
  }
}

export async function oktaBrowserDeviceAuthFlow({
  username,
  password,
  verificationUrl,
  userCode,
}: DeviceFlowInformation & UserPassCredentials): Promise<void> {
  let browser: Browser | undefined;
  try {
    const normalizeUserCode = (str: string) => str.replace(/-/g, '');
    browser = await spawnBrowser(verificationUrl, true);
    await waitForTitle(browser, 'Activate your device', 'h2');
    await ensureValue(
      browser,
      'input[name="userCode"]',
      userCode,
      normalizeUserCode
    );
    await browser.$('input[type="submit"]').click();

    await waitForTitle(browser, 'Sign In', 'h2');
    await ensureValue(browser, 'input[name="identifier"]', username);
    await ensureValue(browser, 'input[name="credentials.passcode"]', password);
    await browser.$('input[type="submit"]').click();

    await waitForTitle(browser, 'Device activated', 'h2');
  } finally {
    await browser?.deleteSession();
  }
}

async function azureSignIn(
  browser: Browser,
  username: string,
  password: string
): Promise<void> {
  await waitForTitle(browser, 'Sign in', 'div[role="heading"]');
  await ensureValue(browser, 'input[name="loginfmt"]', username);
  await browser.$('input[type="submit"]').click();
  await waitForTitle(browser, 'Enter password', 'div[role="heading"]');
  await ensureValue(browser, 'input[name="passwd"]', password);
  await browser.$('input[type="submit"]').click();
}

export async function azureBrowserAuthCodeFlow({
  username,
  password,
  url,
}: OpenBrowserOptions & UserPassCredentials): Promise<void> {
  let browser: Browser | undefined;
  try {
    browser = await spawnBrowser(url, true);
    await azureSignIn(browser, username, password);
    await waitForLocalhostRedirect(browser);
  } finally {
    await browser?.deleteSession();
  }
}

export async function azureBrowserDeviceAuthFlow({
  username,
  password,
  verificationUrl,
  userCode,
}: DeviceFlowInformation & UserPassCredentials): Promise<void> {
  let browser: Browser | undefined;
  try {
    const normalizeUserCode = (str: string) => str.replace(/-/g, '');
    browser = await spawnBrowser(verificationUrl, true);
    await waitForTitle(browser, /Enter code/, 'div[role="heading"]');
    await ensureValue(
      browser,
      'input[name="otc"]',
      userCode,
      normalizeUserCode
    );
    await browser.$('input[type="submit"]').click();
    await azureSignIn(browser, username, password);

    await waitForTitle(
      browser,
      /Are you trying to sign in to/i,
      'div[role="heading"]'
    );
    await browser.$('input[type="submit"]').click();

    await waitForTitle(browser, /^[a-zA-Z0-9_]+$/, 'div[role="heading"]');
  } finally {
    await browser?.deleteSession();
  }
}
