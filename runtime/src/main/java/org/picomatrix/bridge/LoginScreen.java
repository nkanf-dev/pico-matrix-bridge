package org.picomatrix.bridge;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.SystemClock;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.*;
import java.util.concurrent.*;

/** In-app login shown only when no valid installed grant is available. */
final class LoginScreen implements AutoCloseable {
    private final Activity activity;
    private final AccountClient account;
    private final ExecutorService work=Executors.newSingleThreadExecutor();
    private final Runnable signedIn;
    private TextView status;
    private EditText email,code;
    private Button send,login;
    private boolean busy,closed;
    private long sendAfter;
    private int dp(int n) {return Math.round(n*activity.getResources().getDisplayMetrics().density);}
    LoginScreen(Activity activity,Runnable signedIn) {
        this.activity=activity;this.signedIn=signedIn;account=new AccountClient(activity);
        activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll=new ScrollView(activity);LinearLayout root=new LinearLayout(activity);root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(40),dp(32),dp(40),dp(32));root.setBackgroundColor(Color.rgb(243,241,232));scroll.addView(root);activity.setContentView(scroll);
        TextView title=new TextView(activity);title.setText("登录 PICO 账号");title.setTextSize(28);title.setTypeface(null,Typeface.BOLD);title.setTextColor(Color.rgb(25,27,24));root.addView(title);
        TextView description=new TextView(activity);description.setText("使用你的 PICO 国际区账号，继续进入应用。");description.setTextSize(16);description.setPadding(0,dp(14),0,dp(22));root.addView(description);
        email=new EditText(activity);email.setSingleLine(true);email.setHint("邮箱地址");email.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);root.addView(email);
        send=new Button(activity);send.setText("发送验证码");root.addView(send);
        code=new EditText(activity);code.setSingleLine(true);code.setHint("邮件验证码");code.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);root.addView(code);
        login=new Button(activity);login.setText("登录");root.addView(login);
        status=new TextView(activity);status.setTextSize(15);status.setPadding(0,dp(12),0,0);root.addView(status);
        send.setOnClickListener(v->{if(busy)return;if(SystemClock.elapsedRealtime()<sendAfter){status.setText("验证码已发送，请查看邮箱。");return;}
            String address=email.getText().toString().trim();run(false,address,null);});
        login.setOnClickListener(v->{if(busy)return;String address=email.getText().toString().trim(),verification=code.getText().toString().trim();code.setText("");run(true,address,verification);});
    }
    private void run(boolean signingIn,String address,String verification) {
        busy=true;send.setEnabled(false);login.setEnabled(false);status.setText(signingIn?"正在登录…":"正在发送验证码…");
        work.execute(()->{
            String message;boolean success=false;
            try {
                if(signingIn) {account.login(address,verification);account.authorize();message="登录成功";}
                else {account.sendCode(address);message="验证码已发送，请查看邮箱。";}
                success=true;
            } catch(IllegalArgumentException e) {message=e.getMessage();}
            catch(Exception e) {message=signingIn?"登录未成功，请检查验证码后重试。":"验证码暂时无法发送，请稍后重试。";}
            String text=message;boolean complete=success;
            activity.runOnUiThread(()->{if(closed || activity.isDestroyed())return;busy=false;send.setEnabled(true);login.setEnabled(true);status.setText(text);
                if(complete && signingIn) signedIn.run();else if(complete) sendAfter=SystemClock.elapsedRealtime()+60000;
            });
        });
    }
    @Override public void close() {closed=true;work.shutdown();}
}
