const axios = require('axios');
const { USER_SERVICE_URL } = require('../../config/app');

const allServicesLogout = async (token) => {
    try {
        const response = await axios.get(`${USER_SERVICE_URL}/user/logout`, {
          headers: {
            'access-token': `${token}`,
          },
        });
        console.log({response});
        if (response.data.status) {
          return response.data.data; 
        } else {
          console.error('Failed to fetch banks');
          return null;
        }
      } catch (error) {
        console.error('Error logging out:', error);
        return null;
      }
};

module.exports = {
    allServicesLogout
}