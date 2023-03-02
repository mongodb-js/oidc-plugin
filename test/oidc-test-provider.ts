import type { AddressInfo } from 'net';
import type { Browser, RemoteOptions } from 'webdriverio';
import { remote as webdriverIoRemote } from 'webdriverio';
import express from 'express';
import { createServer as createHTTPServer } from 'http';
import OIDCProvider from 'oidc-provider';
import type { IssuerMetadata } from 'openid-client';
import { Issuer } from 'openid-client';
import type { Server as HTTPServer } from 'http';
import type { DeviceFlowInformation, OpenBrowserOptions } from '../src';

import type {
  Configuration as OIDCProviderConfiguration,
  ClientMetadata as OIDCClientMetadata,
} from 'oidc-provider';
import path from 'path';
import { once } from 'events';
import type { OIDCMechanismServerStep1 } from '../src';

const oidcClientConfig: Readonly<OIDCClientMetadata> = {
  client_id: 'zELcpfANLqY7Oqas',
  client_secret:
    'TQV5U29k1gHibH5bx1layBo0OSAvAbRT3UYW3EWrSYBB5swxjVfWUa1BS8lqzxG/0v9wruMcrGadany3',
  grant_types: [
    'refresh_token',
    'authorization_code',
    'urn:ietf:params:oauth:grant-type:device_code',
  ],
  redirect_uris: ['http://localhost:27097/redirect'],
  application_type: 'native',
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
          sign: { alg: 'ES256' },
        },
      }),
    },
  },
  jwks: {
    keys: [
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
      {
        crv: 'P-256',
        d: 'K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws',
        kty: 'EC',
        use: 'sig',
        x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
        y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
      },
    ],
  },
  issueRefreshToken: () => true,
};

export class OIDCTestProvider {
  public accessTokenTTLSeconds: number | undefined;
  public refreshTokenTTLSeconds: number | undefined;

  public httpServer: HTTPServer;
  private issuerMetadata: IssuerMetadata;

  private constructor() {
    this.httpServer = createHTTPServer();
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
    app.use(oidcProvider.callback());

    this.issuerMetadata = (
      await Issuer.discover(`http://localhost:${port}`)
    ).metadata;
    return this;
  }

  public static async create(): Promise<OIDCTestProvider> {
    return await new this().init();
  }

  public async close(): Promise<void> {
    this.httpServer.close();
    await once(this.httpServer, 'close');
  }

  public getMongodbOIDCDBInfo(): OIDCMechanismServerStep1 {
    return {
      clientId: oidcClientConfig.client_id,
      clientSecret: oidcClientConfig.client_secret,

      authorizationEndpoint: this.issuerMetadata.authorization_endpoint,
      tokenEndpoint: this.issuerMetadata.token_endpoint,
      deviceAuthorizationEndpoint: String(
        this.issuerMetadata.device_authorization_endpoint
      ),
    };
  }
}

let canSpawnRegularBrowser = true;
async function spawnBrowser(url: string): Promise<Browser> {
  const options: RemoteOptions = {
    capabilities: { browserName: 'chrome' },
    waitforTimeout: 10_000,
    waitforInterval: 100,
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
  function deleteNodeOptions({ env }) {
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

async function waitForTitle(browser: Browser, expected: string): Promise<void> {
  await browser.waitUntil(async () => {
    const actual = (await browser.$('h1').getText()).trim();
    if (actual !== expected) {
      throw new Error(`Wanted title "${expected}", saw "${actual}"`);
    }
    return true;
  });
}

async function ensureValue(
  browser: Browser,
  selector: string,
  value: string | number
): Promise<void> {
  const el = await browser.$(selector);
  await el.waitForDisplayed();
  await el.setValue(value);
  await browser.waitUntil(async () => {
    const actual = await el.getValue();
    if (actual !== value) {
      await el.setValue(value); // attempt to set value again before continuing
      throw new Error(
        `Wanted value "${value}" for element "${selector}", saw "${actual}"`
      );
    }
    return true;
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

    await waitForTitle(browser, 'Authorize');
    await browser.$('button[type="submit"][autofocus]').click();
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
  } catch (err: unknown) {
    await dumpHtml(browser);
    throw err;
  } finally {
    await browser?.deleteSession();
  }
}
