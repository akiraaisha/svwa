delete_thread = function(id) {
    $.post($SCRIPT_ROOT + 'thread/delete/' + id, function(data) {
        if (data.delete){
            $('.thread#' + id).remove();
        } else {
            flash("Unable to delete thread " + id);
        }
    });
};
