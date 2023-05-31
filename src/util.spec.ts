import { expect } from 'chai';
import { validateSecureHTTPUrl } from './util';

// Helper for avoiding many try/catches in this test
function getErr(cb: () => void): any {
  try {
    cb();
  } catch (err) {
    return err;
  }
  return null;
}

describe('validateSecureHTTPUrl', function () {
  it('validates arguments as either local or HTTPS URLs', function () {
    expect(getErr(() => validateSecureHTTPUrl(null, ''))).to.equal(null);
    expect(getErr(() => validateSecureHTTPUrl(undefined, ''))).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('http://localhost/', ''))
    ).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('https://localhost/', ''))
    ).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('https://mongodb.net/', ''))
    ).to.equal(null);
    expect(getErr(() => validateSecureHTTPUrl('', ''))).to.be.an('Error');
    expect(getErr(() => validateSecureHTTPUrl('asdf', ''))).to.be.an('Error');
    expect(
      getErr(() => validateSecureHTTPUrl('mongodb://localhost/', ''))
    ).to.be.an('Error');
    expect(
      getErr(() => validateSecureHTTPUrl('http://mongodb.net/', ''))
    ).to.be.an('Error');
    expect(
      getErr(() => validateSecureHTTPUrl('http://127.0.0.1/', ''))
    ).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('http://127.255.255.255/', ''))
    ).to.equal(null);
    expect(getErr(() => validateSecureHTTPUrl('http://[::1]/', ''))).to.equal(
      null
    );
    expect(getErr(() => validateSecureHTTPUrl('https://[::1]/', ''))).to.equal(
      null
    );
    expect(
      getErr(() => validateSecureHTTPUrl('http://[::1]:1234/', ''))
    ).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('http://127.0.0.1:1234/', ''))
    ).to.equal(null);
    expect(
      getErr(() => validateSecureHTTPUrl('http://localhost:1234/', ''))
    ).to.equal(null);
  });

  it('includes a diagnostic identifier in the error message', function () {
    expect(
      getErr(() => validateSecureHTTPUrl('mongodb://localhost/', '<some url>'))
        .message
    ).to.include('(validating: <some url>)');
  });
});
