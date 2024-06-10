import { determineLoggedInStatus } from '../controllers/signinAndSignupControllers/determineLoggedInStatus';

describe('determineLoggedInStatus', () => {
    it('should set loggedIn to true and userId when token is valid', () => {
      const req = { cookies: { token: 'validToken' } };
      const { loggedIn, userId } = determineLoggedInStatus(req);
      expect(loggedIn).toBe(true);
      expect(userId).toBe('6665ce8330f37b766806b927');
    });

});