package org.picomatrix.bridge;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService work=Executors.newSingleThreadExecutor();
    private TextView status;
    private EditText email,code;
    private Button send,login,connect,launch;
    private AccountClient account;
    private long sendAfter;
    private boolean busy;
    private interface Action { String run() throws Exception; }
    private int dp(int value) { return Math.round(value*getResources().getDisplayMetrics().density); }
    private TextView text(String value,int size,int color) {
        TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(color);t.setPadding(0,dp(8),0,dp(8));return t;
    }
    private Button button(LinearLayout root,String value) {
        Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setMinHeight(dp(52));root.addView(b,new LinearLayout.LayoutParams(-1,-2));return b;
    }
    private void run(Action action) { run(action,null); }
    private void run(Action action,Runnable afterSuccess) {
        if(busy) return;busy=true;send.setEnabled(false);login.setEnabled(false);connect.setEnabled(false);launch.setEnabled(false);status.setText("正在连接 PICO…");
        work.execute(()->{
            String result;boolean succeeded=false;
            try { result=action.run();succeeded=true; }
            catch(AccountClient.Failure|IllegalArgumentException e) { result=e.getMessage(); }
            catch(Exception e) { result="暂时无法完成，请稍后重试。";android.util.Log.w("MatrixBridge","account UI failed: "+e.getClass().getSimpleName()); }
            String message=result;boolean completed=succeeded;
            runOnUiThread(()->{ if(isDestroyed()) return;busy=false;status.setText(message);send.setEnabled(true);login.setEnabled(true);connect.setEnabled(true);launch.setEnabled(true);if(completed && afterSuccess!=null) afterSuccess.run(); });
        });
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        account=new AccountClient(this);
        ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(40),dp(24),dp(40),dp(32));root.setBackgroundColor(Color.rgb(243,241,232));scroll.addView(root);setContentView(scroll);
        TextView brand=text("P/  MATRIX BRIDGE",15,Color.rgb(172,54,31));brand.setTypeface(null,Typeface.BOLD);root.addView(brand);
        root.addView(text("连接你的 PICO 账号",28,Color.rgb(25,27,24)));
        root.addView(text("使用拥有 Virtual Desktop 的 PICO 国际区账号登录。连接完成后，点击下方按钮打开应用。",16,Color.DKGRAY));
        email=new EditText(this);email.setHint("PICO 账号邮箱");email.setSingleLine(true);email.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);root.addView(email);
        send=button(root,"发送验证码");
        code=new EditText(this);code.setHint("邮件验证码");code.setSingleLine(true);code.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);root.addView(code);
        login=button(root,"登录");connect=button(root,"连接 Virtual Desktop");
        launch=button(root,"打开 Virtual Desktop");
        status=text("尚未登录",16,Color.DKGRAY);root.addView(status);
        Button logout=button(root,"退出登录");
        send.setOnClickListener(v->{ String address=email.getText().toString().trim();if(android.os.SystemClock.elapsedRealtime()<sendAfter){status.setText("验证码已发送，请查看邮箱。");return;}sendAfter=android.os.SystemClock.elapsedRealtime()+60000;run(()->{account.sendCode(address);return "验证码已发送，请查看邮箱。";}); });
        login.setOnClickListener(v->{String address=email.getText().toString().trim(),verification=code.getText().toString().trim();code.setText("");run(()->{account.login(address,verification);return "已登录。点击「连接 Virtual Desktop」继续。";});});
        connect.setOnClickListener(v->run(()->{account.authorize();return "Virtual Desktop 已连接，可以打开应用了。";}));
        launch.setOnClickListener(v->run(()->{GrantInstaller.provision(this);return "已连接，正在打开 Virtual Desktop…";}));
        logout.setOnClickListener(v->{ try {account.logout();status.setText("已退出登录");}catch(Exception e){status.setText("无法退出，请重试。");} });
        run(()->account.status());
    }
    @Override protected void onDestroy() { super.onDestroy();work.shutdown(); }
}
