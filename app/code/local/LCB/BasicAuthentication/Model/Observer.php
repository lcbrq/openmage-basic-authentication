<?php

/**
 * @author Tomasz Gregorczyk <tomasz@silpion.com.pl>
 */
class LCB_BasicAuthentication_Model_Observer
{
    /**
     * @var bool
     */
    private $_authenticationRequired  = false;

    /**
     * @param  Varien_Event_Observer $observer
     * @return void
     */
    public function checkBasicAuthentication(Varien_Event_Observer $observer)
    {
        if (Mage::app()->getStore()->isAdmin() && Mage::getStoreConfigFlag('lcb_basic_authentication/admin/enabled')) {
            $config = Mage::getStoreConfig('lcb_basic_authentication/admin');
            if (isset($config['enabled']) && $config['enabled']) {
                $basicAuthUsername = $config['username'];
                $basicAuthPassword = Mage::getModel('core/encryption')->decrypt($config['password']);
                if ($basicAuthPassword && $basicAuthPassword) {
                    $this->_authenticationRequired = true;
                    list($username, $password) = Mage::helper('core/http')->authValidate();
                    if ($basicAuthUsername !== $username || $password !== $basicAuthPassword) {
                        Mage::helper('core/http')->authFailed();
                    }
                }
            }
        } else {
            $storeId = Mage::app()->getStore()->getId();
            $config = Mage::getStoreConfig('lcb_basic_authentication/frontend', $storeId);

            if (!empty($config['enabled']) && !empty($config['ignored_actions'])) {
                if ($ignoredActions = explode(',', $config['ignored_actions'])) {
                    $request = $observer->getEvent()->getControllerAction()->getRequest();
                    $routeName = $request->getRouteName();
                    $controllerName  = $request->getControllerName();
                    $actionName = $request->getActionName();
                    $fullPath = $routeName . '_' . $controllerName . '_' . $actionName;
                    if (in_array($fullPath, $ignoredActions)) {
                        $config['enabled'] = 0;
                    }
                }
            }

            if (!empty($config['enabled']) && $config['enabled']) {
                $basicAuthUsername = $config['username'];
                $basicAuthPassword = Mage::getModel('core/encryption')->decrypt($config['password']);
                if ($basicAuthPassword && $basicAuthPassword) {
                    $this->_authenticationRequired = true;
                    list($username, $password) = Mage::helper('core/http')->authValidate();
                    if ($basicAuthUsername !== $username || $password !== $basicAuthPassword) {
                        Mage::helper('core/http')->authFailed();
                    }
                }
            }
        }
    }

    /**
     * Fix issue with Lesti Full Page Cache
     * @param  Varien_Event_Observer $observer
     * @return void
     */
    public function onFpcCollectParams(Varien_Event_Observer $observer)
    {
        if ($this->_authenticationRequired) {
            if ($parameters = $observer->getParameters()) {
                if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                    $params = $parameters->getValue();
                    $params['authorization'] = $_SERVER['HTTP_AUTHORIZATION'];
                    $parameters->setValue($params);
                }
            }
        }
    }
}
