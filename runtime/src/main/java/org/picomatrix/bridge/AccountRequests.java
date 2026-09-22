package org.picomatrix.bridge;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import java.util.concurrent.Semaphore;
import org.json.JSONObject;
import org.picomatrix.bridge.protocol.MatrixContract;
import org.picomatrix.bridge.protocol.Wire;

/** Original Matrix request contract, served inside the target process. */
final class AccountRequests {
    private static final Semaphore slots=new Semaphore(2);
    static Bundle call(Context context, Bundle extras) {
        Bundle result=new Bundle();
        if(extras==null) throw new IllegalArgumentException("Unknown operation");
        if(!slots.tryAcquire()) { result.putInt("status",-10001);return result; }
        try {
            AccountClient account=new AccountClient(context);
            int command=extras.getInt("command");byte[] request=extras.getByteArray("request");
            Wire envelope=Wire.parse(request);
            if(envelope.number(MatrixContract.Request.cmd,-1)!=command ||
                !account.identity().appId.equals(envelope.string(MatrixContract.Request.appKey)) ||
                !account.identity().packageName.equals(envelope.string(MatrixContract.Request.appPkg)))
                throw new SecurityException("Application request identity differs");
            if(command!=MatrixContract.CMD_GET_ACCESS_INFO_SILENCE && command!=MatrixContract.CMD_GET_OPEN_USER_INFO && command!=MatrixContract.CMD_GET_OPEN_ACCESS_TOKEN)
                throw new IllegalArgumentException("Unknown account command");
            Wire body=Wire.parse(envelope.bytes(MatrixContract.Request.body));
            if(command==MatrixContract.CMD_GET_OPEN_ACCESS_TOKEN) {
                Wire tokenRequest=Wire.parse(body.bytes(MatrixContract.RequestBody_getAccessTokenRequest));
                for(String scope:tokenRequest.strings(MatrixContract.GetAccessTokenRequest.forceNeedScopes))
                    if(!"user_info".equals(scope)) throw new AccountClient.Failure(-10005,"Requested scope is not connected");
            }
            JSONObject session=account.access();
            JSONObject token=session.getJSONObject("platform");String access=token.getString("access_token");
            Wire.Builder response=new Wire.Builder();
            if(command==MatrixContract.CMD_GET_ACCESS_INFO_SILENCE) {
                response.bytes(MatrixContract.ResponseBody_getAccessInfoSilenceResponse,new Wire.Builder()
                    .string(MatrixContract.GetAccessInfoSilenceResponse.accessToken,access)
                    .string(MatrixContract.GetAccessInfoSilenceResponse.openUid,token.getString("open_id")).build());
            } else if(command==MatrixContract.CMD_GET_OPEN_ACCESS_TOKEN) {
                response.bytes(MatrixContract.ResponseBody_getAccessTokenResponse,new Wire.Builder()
                    .string(MatrixContract.GetAccessTokenResponse.accessToken,access)
                    .string(MatrixContract.GetAccessTokenResponse.authorizedScopes,"user_info").build());
            } else {
                JSONObject user=session.getJSONObject("user");
                Wire.Builder info=new Wire.Builder().string(MatrixContract.OpenUserInfo.openUid,user.getString("account_id"))
                    .string(MatrixContract.OpenUserInfo.accountId,user.getString("account_id"))
                    .string(MatrixContract.OpenUserInfo.accessToken,access)
                    .string(MatrixContract.OpenUserInfo.displayName,user.optString("nick_name"))
                    .string(MatrixContract.OpenUserInfo.picoId,user.optString("pico_id"))
                    .string(MatrixContract.OpenUserInfo.avatarUrl,user.optString("profile"))
                    .string(MatrixContract.OpenUserInfo.smallImageUrl,user.optString("small_image_url"))
                    .string(MatrixContract.OpenUserInfo.secUid,user.optString("sec_uid"))
                    .number(MatrixContract.OpenUserInfo.gender,user.optInt("gender"))
                    .number(MatrixContract.OpenUserInfo.status,user.optInt("status"));
                response.bytes(MatrixContract.ResponseBody_getCurrentOpenUserInfoResponse,new Wire.Builder()
                    .bytes(MatrixContract.GetCurrentOpenUserInfoResponse.loginUser,info.build()).build());
            }
            result.putByteArray("body",response.build());result.putInt("status",0);
            Log.i("MatrixBridge","account command="+command+" completed");
        } catch(AccountClient.Failure e) { result.putInt("status",e.code);result.putString("error",e.getMessage()); }
        catch(Exception e) { result.putInt("status",-10001);result.putString("error","Account request unavailable");Log.w("MatrixBridge","account request failed: "+e.getClass().getSimpleName()); }
        finally { slots.release(); }
        return result;
    }
}
