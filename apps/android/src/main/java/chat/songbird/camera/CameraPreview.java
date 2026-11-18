package chat.songbird.camera;

import android.view.View;

import androidx.camera.view.PreviewView;

import com.longbridge.nsh.NshComponent;
import com.longbridge.nsh.NshComponentContext;

/**
 * The native component {@code songbird/camera}: CameraX's {@link PreviewView} showing the
 * session its {@code session} prop names (D-0113).
 */
public final class CameraPreview implements NshComponent {
    private final PreviewView view;

    public CameraPreview(NshComponentContext context) {
        view = new PreviewView(context.getContext());
        view.setScaleType(PreviewView.ScaleType.FILL_CENTER);
        // A TextureView: it clips to the rounded box NSH lays out, which a SurfaceView does not.
        view.setImplementationMode(PreviewView.ImplementationMode.COMPATIBLE);
    }

    @Override
    public View view() {
        return view;
    }

    @Override
    public void setProp(String name, Object value) {
        if (!"session".equals(name)) return;
        long id = value instanceof Number ? ((Number) value).longValue() : 0;
        CameraBridge.attachPreview(id, view);
    }

    @Override
    public void destroy() {
        CameraBridge.detachPreview(view);
    }
}
