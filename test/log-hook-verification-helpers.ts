import { expect } from 'chai';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function verifySuccessfulAuthCodeFlowLog(entries: any[]) {
  for (const expected of [
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_011,
      ctx: 'test-oidc',
      msg: 'Authentication attempt started',
      attr: { flow: 'auth-code' },
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_005,
      ctx: 'test-oidc',
      msg: 'Started listening on local server',
      attr: (attr) =>
        expect(attr.url).to.match(/http:\/\/localhost.*\/redirect/),
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_007,
      ctx: 'test-oidc',
      msg: 'Successfully listening on local server',
      attr: (attr) => {
        expect(attr.url).to.match(/http:\/\/localhost.*\/redirect/);
        expect(attr.interfaces).to.be.an('array');
        expect(attr.interfaces).to.have.lengthOf.greaterThanOrEqual(1);
        for (const item of attr.interfaces) expect(item).to.be.a('string');
      },
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_009,
      ctx: 'test-oidc',
      msg: 'Opening browser',
      attr: { customOpener: true },
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_001,
      ctx: 'test-oidc',
      msg: 'Local redirect accessed',
      attr: (attr) => expect(attr.id).to.be.a('string'),
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_002,
      ctx: 'test-oidc',
      msg: 'OIDC callback accepted',
      attr: { method: 'GET', hasBody: false, errorCode: null },
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_008,
      ctx: 'test-oidc',
      msg: 'Local server closed',
      attr: (attr) =>
        expect(attr.url).to.match(/http:\/\/localhost.*\/redirect/),
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_008,
      ctx: 'test-oidc',
      msg: 'Local server closed',
      attr: (attr) =>
        expect(attr.url).to.match(/http:\/\/localhost.*\/redirect/),
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_013,
      ctx: 'test-oidc',
      msg: 'Authentication attempt succeeded',
    },
    {
      t: { $date: '2021-12-16T14:35:08.763Z' },
      s: 'I',
      c: 'OIDC-PLUGIN',
      id: 1_002_000_017,
      ctx: 'test-oidc',
      msg: 'Authentication succeeded',
      attr: (attr) => {
        expect(attr.hasRefreshToken).to.equal(true);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        expect(new Date(attr.expiresAt).toISOString()).to.equal(attr.expiresAt);
      },
    },
  ] as const) {
    const found = entries.find(({ id }) => expected.id === id);
    expect(found).to.exist;
    const { attr: foundAttr, ...foundProps } = found;
    const { attr: expectedAttr, ...expectedProps } = expected;
    expect(foundProps).to.deep.equal(expectedProps);
    if (typeof expectedAttr === 'function') {
      expectedAttr(foundAttr);
    } else {
      expect(foundAttr).to.deep.equal(expectedAttr);
    }
  }
}
