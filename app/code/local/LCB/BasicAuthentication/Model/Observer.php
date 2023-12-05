<?php
/**
 * @author Tomasz Gregorczyk <tomasz@silpion.com.pl>
 */
class LCB_BasicAuthentication_Model_Observer
{
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
                    list($username, $password) = Mage::helper('core/http')->authValidate();
                    if ($basicAuthUsername !== $username || $password !== $basicAuthPassword) {
                        Mage::helper('core/http')->authFailed();
                    }
                }
            }
        } else {
            $storeId = Mage::app()->getStore()->getId();
            $config = Mage::getStoreConfig('lcb_basic_authentication/frontend', $storeId);
            if (isset($config['enabled']) && $config['enabled']) {
                $basicAuthUsername = $config['username'];
                $basicAuthPassword = Mage::getModel('core/encryption')->decrypt($config['password']);
                if ($basicAuthPassword && $basicAuthPassword) {
                    list($username, $password) = Mage::helper('core/http')->authValidate();
                    if ($basicAuthUsername !== $username || $password !== $basicAuthPassword) {
                        Mage::helper('core/http')->authFailed();
                    }
                }
            }
        }
    }
}
