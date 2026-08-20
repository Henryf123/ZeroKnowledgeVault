import atexit
from src.database import init_db, get_db, checkpoint_db
from src.workspace import startup_cleanup, shred_path
from src.ui.app import VaultApp

def main():
    startup_cleanup()
    init_db()
    
    db_conn = get_db()
    app = VaultApp(db_conn)
    
    @atexit.register
    def cleanup():
        if app.active_temp_dir:
            shred_path(app.active_temp_dir)
        
        current_db = getattr(app, 'db', None)
        
        if current_db:
            try:
                checkpoint_db(current_db)
                current_db.close()
            except Exception:
                pass

    app.run()

if __name__ == "__main__":
    main()