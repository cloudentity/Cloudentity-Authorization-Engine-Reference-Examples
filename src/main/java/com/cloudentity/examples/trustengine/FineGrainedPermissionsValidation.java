package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.trustengine.client.ApiClient;
import com.cloudentity.libs.trustengine.client.api.AuthzApi;
import com.cloudentity.libs.trustengine.client.model.ValidatorsData;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static com.cloudentity.examples.trustengine.config.Credentials.*;
import static com.cloudentity.examples.trustengine.helpers.Commons.*;

/**
 *
 *  this class shows how to validate fine grained policy without user context (object and princcipal is taken from validation attributes)
 *
 * if run before PermissionManagement this example validation should fail
 * PermissionManagement should set proper permission so that below code should pass
 */
public class FineGrainedPermissionsValidation {

  private static Logger log = LoggerFactory.getLogger(FineGrainedPermissionsValidation.class);

  private static final ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  private static AuthzApi authorizationServiceClient = client.buildClient(AuthzApi.class);

  /**
   *  As in Fine Grained Permission validator access to parameters is done via 'attributes' key we need to create body
   *  with root object 'attributes' and put key-pair 'userUuid' and 'fileId' inside as visible on CAN_ACCESS policy screenshot
   */
  private static final String validationAttributeFieldName = "attributes";
  private static Map<String, String> mapWithAttributesSendForPermissionValidation = new HashMap<String, String>() {
    {
      this.put("userUuid", userUuid);
      this.put("fileId", fileName);
    }
  };

  public static void main(String[] args) {
    ValidatorsData validationInput = new ValidatorsData();
    validationInput.put(validationAttributeFieldName, mapWithAttributesSendForPermissionValidation);
    try {
      log.info("Validating if policy {} holds for user {} and file {}", fineGrainedPolicyName, userUuid, fileName);
      authorizationServiceClient.postAuthzApplicationPolicyWithPolicyNameValidate(fineGrainedPolicyName, null, validationInput);
      log.info("Policy validated successfully");
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }
}
