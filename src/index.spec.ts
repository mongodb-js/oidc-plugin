import { expect } from 'chai';
import { dummy } from './';

describe('dummy', function () {
  it('works', function () {
    expect(dummy()).to.equal(0);
  });
});
