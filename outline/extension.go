package outline_lib

func (c *Client) GetAccessKeyByID(id string) (result AccessKey, err error) {
	if len(c.accessKeysCache) == 0 {
		accessKeysResponse, err := c.GetListAccessKeys()
		if err != nil {
			return result, err
		}
		c.accessKeysCache = accessKeysResponse.AccessKeys
	}
	for _, key := range c.accessKeysCache {
		if key.Id == id {
			return key, nil
		}
	}
	return
}

func (c *Client) CheckAccessKeyByID(id string) (result bool, err error) {
	if len(c.accessKeysCache) == 0 {
		accessKeysResponse, err := c.GetListAccessKeys()
		if err != nil {
			return false, err
		}
		c.accessKeysCache = accessKeysResponse.AccessKeys
	}
	for _, key := range c.accessKeysCache {
		if key.Id == id {
			return true, nil
		}
	}
	return
}

func (c *Client) GetNumberOfUsers() (int, error) {
	if len(c.accessKeysCache) == 0 {
		accessKeysResponse, err := c.GetListAccessKeys()
		if err != nil {
			return 0, err
		}
		c.accessKeysCache = accessKeysResponse.AccessKeys
	}
	return len(c.accessKeysCache), nil
}

func (c *Client) GetNumberOfActiveUsers() (int, error) {
	if c.transferredDataCache == nil {
		resp, err := c.DataTransferredAccessKey()
		if err != nil {
			return 0, err
		}
		c.transferredDataCache = resp.BytesTransferredByUserId
	}
	return len(c.transferredDataCache), nil
}

func (c *Client) DeleteAllKeysWithOutTraffic() (result bool, err error) {
	if c.transferredDataCache == nil {
		resp, err := c.DataTransferredAccessKey()
		if err != nil {
			return false, err
		}
		c.transferredDataCache = resp.BytesTransferredByUserId
	}

	if len(c.accessKeysCache) == 0 {
		accessKeysResponse, err := c.GetListAccessKeys()
		if err != nil {
			return false, err
		}
		c.accessKeysCache = accessKeysResponse.AccessKeys
	}

	for _, accessKey := range c.accessKeysCache {
		if _, ok := c.transferredDataCache[accessKey.Id]; !ok {
			_, err := c.DeleteAccessKey(accessKey.Id)
			if err != nil {
				return false, err
			}
		}
	}
	return true, nil
}
