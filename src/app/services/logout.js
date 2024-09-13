const axios = require('axios');
const { USER_SERVICE_URL } = require('../../config/app');
const Logger = require('../../utils/logger');

const allServicesLogout = async (token) => {
    try {
        const response = await axios.get(`${USER_SERVICE_URL}/user/logout`, {
          headers: {
            'access-token': `${token}`,
          },
        });
        if (response.data.status) {
          return response.data.data; 
        } else {
          Logger.error('Failed to fetch banks');
          return null;
        }
      } catch (error) {
        Logger.error('Error logging out:', error);
        return null;
      }
};

module.exports = {
    allServicesLogout
}