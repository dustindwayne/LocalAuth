package com.localauth

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.content.res.ColorStateList
import android.view.View
import android.view.Gravity
import android.widget.*

object Design {
    val bg = Color.rgb(12,17,25)
    val surface = Color.rgb(22,30,41)
    val text = Color.rgb(237,242,249)
    val muted = Color.rgb(149,164,183)
    val accent = Color.rgb(138,235,193)
    fun dp(c: Context, n: Int) = (n*c.resources.displayMetrics.density).toInt()
    fun shape(c: Context, color: Int, radius: Int = 20) = GradientDrawable().apply { setColor(color); cornerRadius=dp(c,radius).toFloat() }
    fun label(c: Context, value: String, size: Float, color: Int = text) = TextView(c).apply { text=value; textSize=size; setTextColor(color); includeFontPadding=false; setLineSpacing(dp(c,4).toFloat(),1f) }
    fun space(c: Context, height: Int) = View(c).apply { layoutParams=LinearLayout.LayoutParams(1,dp(c,height)); importantForAccessibility=View.IMPORTANT_FOR_ACCESSIBILITY_NO }
    fun action(c: Context, value: String, primary: Boolean = true, run: () -> Unit) = Button(c).apply {
        text=value; textSize=15f; isAllCaps=false; typeface=Typeface.create("sans-serif-medium",Typeface.NORMAL)
        setTextColor(if(primary) Design.bg else Design.text)
        background=RippleDrawable(ColorStateList.valueOf(0x248AEBC1),shape(c,if(primary) accent else surface,16),null)
        minHeight=dp(c,54); minimumHeight=dp(c,54); setPadding(dp(c,18),dp(c,10),dp(c,18),dp(c,10))
        layoutParams=LinearLayout.LayoutParams(-1,dp(c,54)).apply { topMargin=dp(c,12) }
        setOnClickListener { run() }
    }
    fun enter(view: View) {
        if (!ValueAnimator.areAnimatorsEnabled()) return
        view.alpha=0f; view.translationY=dp(view.context,10).toFloat()
        view.animate().alpha(1f).translationY(0f).setDuration(240).start()
    }
}

class FingerprintArt(context: Context) : View(context) {
    private val paint=Paint(Paint.ANTI_ALIAS_FLAG)
    private var phase=0f
    private var animation: ValueAnimator? = null
    init { contentDescription="Fingerprint authentication"; importantForAccessibility=IMPORTANT_FOR_ACCESSIBILITY_NO }
    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if(ValueAnimator.areAnimatorsEnabled()) animation=ValueAnimator.ofFloat(0f,1f).apply {
            duration=2200; repeatCount=ValueAnimator.INFINITE; repeatMode=ValueAnimator.REVERSE
            addUpdateListener { phase=it.animatedValue as Float; invalidate() }; start()
        }
    }
    override fun onDetachedFromWindow() { animation?.cancel(); animation=null; super.onDetachedFromWindow() }
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size=minOf(width,height).toFloat(); val x=width/2f; val y=height/2f
        paint.style=Paint.Style.FILL; paint.color=Design.accent; paint.alpha=(12+phase*8).toInt()
        canvas.drawCircle(x,y,size*.43f+phase*size*.02f,paint)
        paint.alpha=255; paint.style=Paint.Style.STROKE; paint.strokeWidth=size*.014f; paint.strokeCap=Paint.Cap.ROUND
        for(i in 0..4) {
            val r=size*(.10f+i*.043f)
            paint.color=Design.accent; paint.alpha=230-i*22
            canvas.drawArc(RectF(x-r,y-r*.9f,x+r,y+r*.9f),195f,240f,false,paint)
            canvas.drawLine(x-r*.85f,y+r*.48f,x-r*.72f,y+r*1.25f,paint)
        }
        paint.alpha=230; val path=Path().apply { moveTo(x,y-size*.05f); cubicTo(x+size*.025f,y+size*.04f,x-size*.02f,y+size*.16f,x+size*.055f,y+size*.25f) }
        canvas.drawPath(path,paint); paint.alpha=255
    }
}

class AccountCard(context: Context, val account: Account, copy: () -> Unit, remove: () -> Boolean) : LinearLayout(context) {
    private val code=Design.label(context,"",32f,Design.accent)
    private val countdown=Design.label(context,"",12f,Design.muted)
    private val progress=ProgressBar(context,null,android.R.attr.progressBarStyleHorizontal)
    private var current=""
    private var codeCounter=-1L
    init {
        orientation=VERTICAL; setPadding(Design.dp(context,22),Design.dp(context,20),Design.dp(context,22),Design.dp(context,20))
        background=RippleDrawable(ColorStateList.valueOf(0x148AEBC1),Design.shape(context,Design.surface),null)
        layoutParams=LayoutParams(-1,-2).apply { topMargin=Design.dp(context,12) }
        val issuer=account.label.substringBefore(':')
        addView(Design.label(context,issuer,16f).apply { typeface=Typeface.create("sans-serif-medium",android.graphics.Typeface.NORMAL); maxLines=2 })
        if(':' in account.label) addView(Design.label(context,account.label.substringAfter(':'),13f,Design.muted).apply { setPadding(0,Design.dp(context,5),0,0); maxLines=2 })
        addView(Design.space(context,20))
        code.typeface=Typeface.create("monospace",Typeface.NORMAL); code.letterSpacing=.06f; code.setAutoSizeTextTypeUniformWithConfiguration(18,32,1,android.util.TypedValue.COMPLEX_UNIT_SP)
        val row=LinearLayout(context).apply { gravity=Gravity.CENTER_VERTICAL }
        row.addView(code,LayoutParams(0,-2,1f)); row.addView(Design.label(context,"COPY",10f,Design.muted).apply { letterSpacing=.12f })
        addView(row); addView(Design.space(context,18))
        progress.max=account.period; progress.progressTintList=ColorStateList.valueOf(Design.accent); progress.progressBackgroundTintList=ColorStateList.valueOf(Color.rgb(42,55,68))
        addView(progress,LayoutParams(-1,Design.dp(context,3)))
        addView(Design.space(context,9)); addView(countdown)
        isClickable=true; isFocusable=true
        setOnClickListener { performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP); copy() }
        setOnLongClickListener { remove() }
    }
    fun update(seconds: Long) {
        if(codeCounter!=seconds/account.period){current="";codeCounter=-1}
        val next=current
        if(next!=current) {
            current=next
            code.text=if(next.isEmpty())"••• •••" else next.chunked(next.length/2).joinToString(" ")
            if(ValueAnimator.areAnimatorsEnabled()) { code.alpha=.45f; code.animate().alpha(1f).setDuration(180).start() }
        }
        if(next.isEmpty())code.text="••• •••"
        val left=account.period-(seconds%account.period).toInt()
        progress.progress=left; countdown.text=if(next.isEmpty())"Touch to scan fingerprint" else "Expires in ${left}s"
        contentDescription=if(next.isEmpty())"${account.label}. Tap to authenticate and copy a code, hold to remove." else "${account.label}. Code expires in $left seconds. Tap to copy, hold to remove."
    }
    fun cachedCode(seconds:Long):String? = current.takeIf {it.isNotEmpty()&&codeCounter==seconds/account.period}
    fun reveal(value:String,seconds:Long){current=value;codeCounter=seconds/account.period;code.text=value.chunked(value.length/2).joinToString(" ");update(seconds);if(ValueAnimator.areAnimatorsEnabled()){code.alpha=.45f;code.animate().alpha(1f).setDuration(180).start()}}
}
