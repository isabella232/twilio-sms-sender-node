
/*
 * Copyright 2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package example.com.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.ONE_TIME_PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.sm.RequiredValueValidator;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

/**
 * A AntiPrivacy node.
 * You can extend:
 * SingleOutcomeNode
 * AbstractDecisionNode
 * Or directly implement the Node interface.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = TwilioSMSSenderNode.Config.class)
public class TwilioSMSSenderNode extends SingleOutcomeNode {

    private final CoreWrapper coreWrapper;
    private final Logger logger = LoggerFactory.getLogger(TwilioSMSSenderNode.class);
    private static final String BUNDLE = TwilioSMSSenderNode.class.getName().replace(".", "/");
    private ResourceBundle resourceBundle;
    private String mobilePhoneAttributeName;
    private String message;
    private String accountSid;
    private String authToken;
    private String twilioPhoneNumber;


    /**
     * Configuration for the node.
     * It can have as many attributes as needed, or none.
     */
    public interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default String mobilePhoneAttributeName() { return "telephoneNumber"; }

        @Attribute(order = 200)
        default String message() { return "message"; }

        @Attribute(order = 300)
        default String twilio_ACCOUNT_SID() { return "ACCOUNT_SID"; }

        @Attribute(order = 400)
        @Password
        char[] twilio_AUTH_TOKEN();
       // default String twilio_AUTH_TOKEN() { return "AUTH_TOKEN"; }

        @Attribute(order = 500)
        default String twilio_PHONE_NUMBER() { return "twilio_PHONE_NUMBER"; }

}


    /*
     * Constructs a new GetSessionPropertiesNode instance.
     * We can have Assisted:
     * * Config config
     * * UUID nodeId
     *
     * We may want to Inject:
     * CoreWrapper
     */
    @Inject
    public TwilioSMSSenderNode(@Assisted Config config, CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;

        this.mobilePhoneAttributeName = config.mobilePhoneAttributeName();
        this.message = config.message();
        this.accountSid = config.twilio_ACCOUNT_SID();
        this.authToken = new String(config.twilio_AUTH_TOKEN());
        this.twilioPhoneNumber = config.twilio_PHONE_NUMBER();
        if (StringUtils.isBlank(mobilePhoneAttributeName)) {
            mobilePhoneAttributeName = "telephoneNumber";
        }
        logger.debug("mobile phone attribute " + mobilePhoneAttributeName);
        logger.debug("message is " + message);
        logger.debug("twilio account SID " + accountSid);
        logger.debug("twilio account TOKEN " + authToken);
        logger.debug("twilio phone number " + twilioPhoneNumber);


    }

    /*
     * From the context you will be able to access:
     * Callbacks
     * Shared State
     * Transient State
     *
     * We have certain Actions prefefined that we can use:
     * send -> send a callback
     * goTo -> go to a different node
     *
     * Look into ActionBuilder to see how to:
     * update shared state
     * add session hooks -> classes that will be executed post-authentication.
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        this.resourceBundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());

        String username = context.sharedState.get(USERNAME).asString();
        String phone = getTelephoneNumber(coreWrapper.getIdentity(username,
                coreWrapper.convertRealmPathToRealmDn(context.sharedState.get(REALM).asString())));
        logger.debug(username + " Phone Number " + phone);

        Twilio.init(accountSid, authToken);
        try {
            String response = Message.creator(new PhoneNumber(phone), new PhoneNumber(twilioPhoneNumber), message +
                    " " + context.sharedState.get(ONE_TIME_PASSWORD).asString()).create().getSid();
            logger.debug("Tracking SID is " + response);
        } catch (Exception e) {
            e.printStackTrace();
            throw new NodeProcessException(resourceBundle.getString("Unable to send HOTP code " + e ));
            //Todo need some way of signifying the message didn't go through. Either with NodeProcessException or
            //a custom outcome provider

        }
        return goToNext().build();
    }

    private String getTelephoneNumber(AMIdentity identity) throws NodeProcessException {
        Set<String> telephoneNumbers;
        try {
            telephoneNumbers = identity.getAttribute(mobilePhoneAttributeName);
        } catch (IdRepoException | SSOException e) {
            e.printStackTrace();
            throw new NodeProcessException(resourceBundle.getString("Unable to get attribute " + mobilePhoneAttributeName));
        }

        if (telephoneNumbers != null && !telephoneNumbers.isEmpty()) {
            String phone = telephoneNumbers.iterator().next();
            if (phone != null) {
                return phone;
            }
        }
        throw new NodeProcessException(resourceBundle.getString("phone.not.found"));
    }

}
