import copy
import unittest
from scripts.deploy_business import validate_cors_exposure

class CorsExposureTests(unittest.TestCase):
    def test_configuration_is_distinct_from_preflight_headers(self):
        origin='https://d3rn3hqm0ax5ux.cloudfront.net'
        config={'AllowOrigins':[origin], 'AllowMethods':['GET','OPTIONS','POST'],
                'AllowHeaders':['authorization','content-type'],'ExposeHeaders':['x-request-id']}
        self.assertEqual(validate_cors_exposure(config,origin),{'x-request-id'})
        for field,value in [('ExposeHeaders',[]),('ExposeHeaders',['*']),
                            ('AllowOrigins',['*']),('AllowHeaders',['authorization']),
                            ('AllowMethods',['GET'])]:
            changed=copy.deepcopy(config);changed[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                validate_cors_exposure(changed,origin)
